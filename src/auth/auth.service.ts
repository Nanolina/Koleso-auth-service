import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ClientProxy } from '@nestjs/microservices';
import { Prisma, User } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { UNKNOWN_ERROR, convertToNumber } from '../common';
import { MyLogger } from '../logger/my-logger.service';
import { PasswordResetTokenService } from '../password-reset-token/password-reset-token.service';
import { PrismaService } from '../prisma/prisma.service';
import { TokenService } from '../token/token.service';
import { UNKNOWN_ERROR_TRY } from './../common/consts';
import {
  ChangeEmailDto,
  ChangeEmailServiceDto,
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
    private passwordResetTokenService: PasswordResetTokenService,
    private configService: ConfigService,
    private readonly logger: MyLogger,
    @Inject('AUTH_CLIENT') private readonly client: ClientProxy,
  ) {}

  async signup(dto: SignupDto): Promise<AuthResponse> {
    // Get data from dto
    const { password, repeatedPassword, email, phone } = dto;

    // Password comparison
    if (password !== repeatedPassword) {
      this.logger.error({ method: 'signup', error: 'Passwords do not match' });

      throw new BadRequestException('Passwords do not match');
    }

    // Hash the password
    const hashedPassword = await this.hashPassword(password);

    // Create a UUID for a future activation link
    const activationLinkId = uuidv4();

    // Create new user
    let newUser;
    try {
      newUser = await this.prisma.user.create({
        data: {
          email,
          phone,
          activationLinkId,
          password: hashedPassword,
        },
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          this.logger.error({
            method: 'signup',
            error: 'A user with the same phone number or email already exists',
          });

          throw new BadRequestException(
            'A user with the same phone number or email already exists',
          );
        }
      }

      this.logger.error({ method: 'signup', error });

      throw new InternalServerErrorException(
        'Something went wrong, please check the data',
      );
    }

    // Create new tokens
    const tokens = await this.createTokensInTokenService(newUser.id);
    const userData: UserData = {
      activationLinkId,
      id: newUser.id,
      email: newUser.email,
      isActive: newUser.isActive,
      isVerifiedEmail: newUser.isVerifiedEmail,
    };

    try {
      await this.client.emit('user_created', {
        activationLinkId,
        email: newUser.email,
      });

      this.logger.log({ method: 'signup', log: 'user_created' });
    } catch (error) {
      this.logger.error({ method: 'signup (user_created event)', error });
    }

    return {
      tokens,
      user: userData,
    };
  }

  async login(dto: LoginDto): Promise<AuthResponse> {
    // Find user by email
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      this.logger.error({
        method: 'login',
        error: 'User not found by his email',
      });

      throw new NotFoundException(
        'This user does not exist, please check the email you registered with',
      );
    }

    // Variables
    const userId: string = user.id;
    const errorIfUserNotActive =
      'Sorry, the number of attempts has been exhausted. Unfortunately, your account has been locked and you can recover it by clicking on the "Forgot password" link';

    if (!user.isActive) {
      this.logger.error({
        method: 'login',
        error: 'User is deactivated',
      });

      throw new ForbiddenException(errorIfUserNotActive);
    }

    // Verify password
    const passwordMatches = await this.verifyPassword(
      dto.password,
      user.password,
    );

    // Increase failed attempts
    if (!passwordMatches) {
      // Variables
      const failedAttempts = user.failedAttempts + 1;
      await this.updateFailedAttempts(userId, failedAttempts);
      const remainingAttempts = 5 - failedAttempts;
      const errorMessage = `Invalid password. Number of remaining attempts: ${remainingAttempts}`;

      // Deactivate user
      if (failedAttempts >= 5) {
        await this.deactivateUser(userId);

        this.logger.error({
          method: 'login',
          error: errorIfUserNotActive,
        });

        throw new ForbiddenException(errorIfUserNotActive);
      }

      this.logger.error({
        method: 'login',
        error: errorMessage,
      });

      throw new BadRequestException(errorMessage);
    }

    // Reset all invalid attempts to 0 in case of a successful login
    await this.resetFailedAttempts(userId);

    // Create new tokens
    const tokens = await this.createTokensInTokenService(userId);
    const userData: UserData = {
      id: userId,
      email: user.email,
      activationLinkId: user.activationLinkId,
      isActive: user.isActive,
      isVerifiedEmail: user.isVerifiedEmail,
    };

    return {
      tokens,
      user: userData,
    };
  }

  async logout(userId: string) {
    await this.tokenService.removeToken(userId);
  }

  async changeEmail(dto: ChangeEmailServiceDto) {
    try {
      const user = await this.prisma.user.update({
        where: {
          id: dto.id,
        },
        data: {
          email: dto.email,
        },
      });

      return {
        email: user.email,
      };
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          this.logger.error({
            method: 'changeEmail',
            error: 'A user with the same email already exists',
          });

          throw new BadRequestException(
            'A user with the same email already exists',
          );
        }
      }

      this.logger.error({ method: 'changeEmail', error });

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

    // Create a password reset token in the database
    const { passwordResetToken } =
      await this.passwordResetTokenService.create(userId);

    // Create an event for notification-service to subscribe and send the link to email
    try {
      await this.client.emit('password_reset_requested', {
        userId,
        email,
        passwordResetToken,
      });

      this.logger.log({
        method: 'requestPasswordRecovery',
        log: 'password_reset_requested',
      });
    } catch (error) {
      this.logger.error({
        method: 'requestPasswordRecovery (password_reset_requested event)',
        error,
      });
    }
  }

  async setNewPassword(dto: SetNewPasswordServiceDto): Promise<AuthResponse> {
    // Get data from dto
    const { userId, password, repeatedPassword } = dto;

    // Password comparison
    if (password !== repeatedPassword) {
      this.logger.error({
        method: 'setNewPassword',
        error: 'Passwords do not match',
      });

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
      this.logger.error({ method: 'setNewPassword', error });

      throw new InternalServerErrorException(
        'Something went wrong, please check the data',
      );
    }

    // Create new tokens
    const tokens = await this.createTokensInTokenService(userId);
    const userData: UserData = {
      activationLinkId: user.activationLinkId,
      id: user.id,
      email: user.email,
      isActive: user.isActive,
      isVerifiedEmail: user.isVerifiedEmail,
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
      this.logger.error({ method: 'hashPassword', error });

      throw new InternalServerErrorException(UNKNOWN_ERROR_TRY);
    }
  }

  async verifyPassword(password, hashedPassword) {
    try {
      return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
      this.logger.error({ method: 'verifyPassword', error });

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
      this.logger.error({ method: 'updateFailedAttempts', error });

      throw new InternalServerErrorException(UNKNOWN_ERROR);
    }
  }

  async verifyEmail(activationLinkId: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        activationLinkId,
      },
    });

    if (!user) {
      this.logger.error({
        method: 'activateUser',
        error: 'User not found by activation link ID',
      });

      throw new NotFoundException(UNKNOWN_ERROR_TRY);
    }

    try {
      await this.prisma.user.update({
        where: {
          id: user.id,
        },
        data: {
          isVerifiedEmail: true,
        },
      });
    } catch (error) {
      this.logger.error({ method: 'activateUser', error });

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
      this.logger.error({ method: 'deactivateUser', error });

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
        method: 'resetFailedAttempts',
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
