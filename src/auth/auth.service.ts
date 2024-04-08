import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ClientProxy } from '@nestjs/microservices';
import { Prisma, User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { UNKNOWN_ERROR, convertToNumber } from '../common';
import { MyLogger } from '../logger/my-logger.service';
import { PrismaService } from '../prisma/prisma.service';
import { RabbitMQService } from '../rabbitmq/rabbitmq.service';
import { TokenService } from '../token/token.service';
import { VerificationCodeService } from '../verification-code/verification-code.service';
import { UNKNOWN_ERROR_TRY } from './../common/consts';
import {
  ChangeEmailDto,
  ChangeEmailServiceDto,
  ChangePasswordServiceDto,
  ChangePhoneServiceDto,
  LoginDto,
  SetNewPasswordServiceDto,
  SignupDto,
} from './dto';
import { AuthResponse, Tokens, UserData } from './types';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private tokenService: TokenService,
    private verificationCodeService: VerificationCodeService,
    private configService: ConfigService,
    private rabbitMQService: RabbitMQService,
    private readonly logger: MyLogger,
    @Inject('AUTH_CLIENT') private readonly client: ClientProxy,
  ) {}

  async signup(dto: SignupDto): Promise<AuthResponse> {
    // Get data from dto
    const { password, repeatedPassword, email, phone, role } = dto;

    // Password comparison
    if (password !== repeatedPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    // Hash the password
    const hashedPassword = await this.hashPassword(password);

    try {
      const newUser = await this.prisma.user.create({
        data: {
          email,
          phone,
          role,
          password: hashedPassword,
        },
      });

      const newUserId = newUser.id;

      // Generate verification code for email confirmation
      const verificationCodeEmail = await this.verificationCodeService.create(
        newUserId,
        'EMAIL_CONFIRMATION',
      );

      const tokens = await this.createTokensInTokenService(newUserId);
      const eventType: string = 'user_created';

      const userCreatedEventData = {
        email,
        eventType,
        id: newUserId,
      };

      const exchange = this.configService.get<string>('RABBITMQ_AUTH_EXCHANGE');
      await this.rabbitMQService.publishToExchange(
        'fanout',
        eventType,
        {
          verificationCodeEmail,
          ...userCreatedEventData,
        },
        exchange,
      );
      this.logger.log({
        method: 'signup',
        log: `user_created event published with id: ${newUserId}`,
      });

      return {
        tokens,
        user: {
          phone,
          role,
          isActive: newUser.isActive,
          isVerifiedEmail: newUser.isVerifiedEmail,
          ...userCreatedEventData,
        },
      };
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        const errorMessage = 'A user with the same email already exists';
        throw new BadRequestException(errorMessage);
      }

      this.logger.error({
        method: 'auth-signup',
        error,
      });
      throw new InternalServerErrorException(UNKNOWN_ERROR_TRY);
    }
  }

  async login(dto: LoginDto): Promise<AuthResponse> {
    // Find user and roles
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // Validate user existence and active status
    if (!user) {
      throw new NotFoundException(
        'This user does not exist, please check the email you registered with',
      );
    }
    if (!user.isActive) {
      throw new ForbiddenException(
        'Your account has been locked. Please recover it by clicking on the "Forgot password" link',
      );
    }

    // Verify the password
    const passwordMatches = await this.verifyPassword(
      dto.password,
      user.password,
    );
    if (!passwordMatches) {
      const failedAttempts = user.failedAttempts + 1;
      await this.updateFailedAttempts(user.id, failedAttempts);

      if (failedAttempts >= 5) {
        await this.deactivateUser(user.id);
        throw new ForbiddenException(
          'Sorry, your account has been locked due to too many failed login attempts',
        );
      }

      throw new BadRequestException(
        `Invalid password. Number of remaining attempts: ${5 - failedAttempts}`,
      );
    }

    // Reset all invalid attempts to 0 in case of a successful login
    await this.resetFailedAttempts(user.id);

    // Create new tokens
    const tokens = await this.createTokensInTokenService(user.id);
    const { role, id, email, phone, isActive, isVerifiedEmail } = user;

    const userData: UserData = {
      id,
      role,
      email,
      phone,
      isActive,
      isVerifiedEmail,
    };

    return { tokens, user: userData };
  }

  async logout(userId: string) {
    await this.tokenService.removeToken(userId);
  }

  async changeEmail(dto: ChangeEmailServiceDto) {
    try {
      const email = dto.email;
      const user = await this.prisma.user.update({
        where: {
          id: dto.id,
        },
        data: {
          email,
          isVerifiedEmail: false,
        },
      });

      const userId = user.id;
      const data = {
        email,
      };

      // Generate verification code for email confirmation
      const verificationCodeEmail = await this.verificationCodeService.create(
        userId,
        'EMAIL_CONFIRMATION',
      );

      await this.client.emit('email_changed', {
        verificationCodeEmail,
        id: userId,
        ...data,
      });
      this.logger.log({
        method: 'changeEmail',
        log: `email_changed event published with id: ${userId}`,
      });

      return {
        isVerifiedEmail: user.isVerifiedEmail,
        ...data,
      };
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new BadRequestException(
            'A user with the same email already exists',
          );
        }
      }

      this.logger.error({ method: 'auth-changeEmail', error });
      throw new InternalServerErrorException(UNKNOWN_ERROR_TRY);
    }
  }

  async changePhone(dto: ChangePhoneServiceDto) {
    try {
      const user = await this.prisma.user.update({
        where: {
          id: dto.id,
        },
        data: {
          phone: dto.phone,
        },
      });

      return {
        phone: user.phone,
      };
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new BadRequestException(
            'A user with the same phone already exists',
          );
        }
      }

      this.logger.error({ method: 'auth-changePhone', error });
      throw new InternalServerErrorException(UNKNOWN_ERROR_TRY);
    }
  }

  async changePassword(dto: ChangePasswordServiceDto): Promise<boolean> {
    const { id, currentPassword, newPassword, repeatedPassword } = dto;

    // Compare new password and repeated password
    if (newPassword !== repeatedPassword) {
      throw new UnauthorizedException(
        'New password and repeated password do not match',
      );
    }

    // Find a user
    const existingUser = await this.prisma.user.findUnique({
      where: { id },
    });

    // Compare the existing password in the DB with the one that came from user
    const isPasswordValid = await bcrypt.compare(
      currentPassword,
      existingUser.password,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Hash the new password
    const hashedNewPassword = await this.hashPassword(newPassword);

    // Update the user's password
    try {
      await this.prisma.user.update({
        where: {
          id,
        },
        data: {
          password: hashedNewPassword,
        },
      });

      return true;
    } catch (error) {
      this.logger.error({ method: 'auth-changePassword', error });
      throw new InternalServerErrorException(UNKNOWN_ERROR_TRY);
    }
  }

  async requestPasswordRecovery(dto: ChangeEmailDto) {
    // Check user with incoming email
    const email = dto.email;
    const user = await this.prisma.user.findFirst({
      where: {
        email,
      },
    });

    if (!user) {
      throw new BadRequestException('The user with this email does not exist');
    }

    const userId = user.id;

    // Generate verification code for reset password
    const verificationCodeEmail = await this.verificationCodeService.create(
      userId,
      'PASSWORD_RESET',
    );

    // Create an event for notification-service to send the verification code
    try {
      await this.client.emit('password_reset_requested', {
        email,
        verificationCodeEmail,
        id: userId,
      });

      this.logger.log({
        method: 'requestPasswordRecovery',
        log: `password_reset_requested event published with userId: ${userId}`,
      });
    } catch (error) {
      this.logger.error({
        method: 'auth-requestPasswordRecovery (password_reset_requested event)',
        error,
      });
    }
  }

  async setNewPassword(dto: SetNewPasswordServiceDto) {
    // Get data from dto
    const { userId, password, repeatedPassword } = dto;

    // Password comparison
    if (password !== repeatedPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    // Hash the password
    const hashedPassword = await this.hashPassword(password);

    let user: User;
    try {
      user = await this.prisma.user.update({
        where: {
          id: userId,
        },
        data: {
          password: hashedPassword,
          isActive: true,
          failedAttempts: 0,
        },
      });
    } catch (error) {
      this.logger.error({ method: 'auth-setNewPassword', error });
      throw new InternalServerErrorException(UNKNOWN_ERROR_TRY);
    }

    // Create new tokens
    const tokens = await this.createTokensInTokenService(userId);
    const { role, id, email, phone, isActive, isVerifiedEmail } = user;

    const userData: UserData = {
      id,
      role,
      email,
      phone,
      isActive,
      isVerifiedEmail,
    };

    return {
      tokens,
      user: userData,
    };
  }

  async hashPassword(password: string) {
    try {
      const bcryptRounds = this.configService.get<string>('BCRYPT_ROUNDS');
      const rounds = convertToNumber(bcryptRounds);
      return await bcrypt.hash(password, rounds);
    } catch (error) {
      this.logger.error({ method: 'auth-hashPassword', error });
      throw new InternalServerErrorException(UNKNOWN_ERROR_TRY);
    }
  }

  async verifyPassword(password, hashedPassword) {
    try {
      return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
      this.logger.error({ method: 'auth-verifyPassword', error });
      throw new InternalServerErrorException(UNKNOWN_ERROR_TRY);
    }
  }

  async updateFailedAttempts(userId: string, attempts: number) {
    try {
      return await this.prisma.user.update({
        where: {
          id: userId,
        },
        data: {
          failedAttempts: attempts,
        },
      });
    } catch (error) {
      this.logger.error({ method: 'auth-updateFailedAttempts', error });
      throw new InternalServerErrorException(UNKNOWN_ERROR);
    }
  }

  async toggleIsVerifiedEmail(userId: string) {
    try {
      const user = await this.prisma.user.update({
        where: {
          id: userId,
        },
        data: {
          isVerifiedEmail: true,
        },
      });

      return { isVerifiedEmail: user.isVerifiedEmail };
    } catch (error) {
      this.logger.error({ method: 'auth-toggleIsVerifiedEmail', error });
      throw new InternalServerErrorException(UNKNOWN_ERROR);
    }
  }

  async deactivateUser(userId: string) {
    try {
      await this.prisma.user.update({
        where: {
          id: userId,
        },
        data: {
          isActive: false,
          deactivationDate: new Date(),
        },
      });
    } catch (error) {
      this.logger.error({ method: 'auth-deactivateUser', error });
      throw new InternalServerErrorException(UNKNOWN_ERROR);
    }
  }

  async resetFailedAttempts(userId: string) {
    try {
      await this.prisma.user.update({
        where: {
          id: userId,
        },
        data: {
          failedAttempts: 0,
        },
      });
    } catch (error) {
      this.logger.error({
        method: 'auth-resetFailedAttempts',
        error,
      });

      throw new InternalServerErrorException(UNKNOWN_ERROR_TRY);
    }
  }

  private async createTokensInTokenService(userId: string): Promise<Tokens> {
    const tokens = await this.tokenService.createTokens(userId);
    await this.tokenService.updateRefreshToken(userId, tokens.refreshToken);
    return tokens;
  }
}
