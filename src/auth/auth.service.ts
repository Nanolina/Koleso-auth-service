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
import { Prisma, RoleType, User } from '@prisma/client';
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
  ChangePasswordServiceDto,
  ChangePhoneServiceDto,
  LoginDto,
  SetNewPasswordServiceDto,
  SignupDto,
} from './dto';
import {
  AuthResponse,
  Tokens,
  UserData,
  UserDataSetNewPassword,
} from './types';

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
    const { password, repeatedPassword, email, phone, role } = dto;

    // Password comparison
    if (password !== repeatedPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    // Hash the password
    const hashedPassword = await this.hashPassword(password);

    // Create a UUID for a future activation link
    const activationLinkId = uuidv4();

    try {
      const newUser = await this.prisma.user.upsert({
        where: { email, phone },
        update: {
          userRoles: {
            create: [
              {
                role: {
                  connectOrCreate: {
                    where: { name: role },
                    create: { name: role },
                  },
                },
              },
            ],
          },
        },
        create: {
          email,
          phone,
          activationLinkId,
          password: hashedPassword,
          userRoles: {
            create: [
              {
                role: {
                  connectOrCreate: {
                    where: { name: role },
                    create: { name: role },
                  },
                },
              },
            ],
          },
        },
        include: {
          userRoles: {
            include: {
              role: true,
            },
          },
        },
      });

      const newUserId = newUser.id;
      const tokens = await this.createTokensInTokenService(newUserId);
      const roles = newUser.userRoles.map((userRole) => userRole.role.name);

      const userCreatedEventData = {
        roles,
        activationLinkId,
        id: newUserId,
        email: newUser.email,
        phone: newUser.phone,
        isActive: newUser.isActive,
        isVerifiedEmail: newUser.isVerifiedEmail,
      };

      await this.client.emit('user_created', userCreatedEventData);
      this.logger.log({
        method: 'signup',
        log: `user_created with id: ${newUserId}`,
      });

      return { tokens, user: userCreatedEventData };
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        const errorMessage =
          'A user with the same phone number or email already exists';
        throw new BadRequestException(errorMessage);
      }

      this.logger.error({
        method: 'signup',
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
      include: {
        userRoles: {
          include: {
            role: {
              select: {
                name: true,
              },
            },
          },
        },
      },
    });

    // Check the roles and if there's a 'Seller' in those roles
    const roles: string[] = user.userRoles.map(
      (userRole) => userRole.role.name,
    );

    if (!roles.some((role) => role === RoleType.Seller)) {
      throw new NotFoundException('This seller does not exist, please sign up');
    }

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
    const userData: UserData = {
      roles,
      id: user.id,
      email: user.email,
      phone: user.phone,
      activationLinkId: user.activationLinkId,
      isActive: user.isActive,
      isVerifiedEmail: user.isVerifiedEmail,
    };

    return { tokens, user: userData };
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
          throw new BadRequestException(
            'A user with the same email already exists',
          );
        }
      }

      this.logger.error({ method: 'changeEmail', error });
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

      this.logger.error({ method: 'changePhone', error });
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
      this.logger.error({ method: 'changePassword', error });
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
        log: `password_reset_requested with userId: ${userId}`,
      });
    } catch (error) {
      this.logger.error({
        method: 'requestPasswordRecovery (password_reset_requested event)',
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
      this.logger.error({ method: 'setNewPassword', error });
      throw new InternalServerErrorException(UNKNOWN_ERROR_TRY);
    }

    // Create new tokens
    const tokens = await this.createTokensInTokenService(userId);
    const userData: UserDataSetNewPassword = {
      isActive: user.isActive,
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
        error: `User not found by activationLinkId: ${activationLinkId}`,
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
