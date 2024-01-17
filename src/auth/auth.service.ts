import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  NotImplementedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { PrismaService } from '../prisma/prisma.service';
import { TokenService } from '../token/token.service';
import { LoginDto, SignupDto } from './dto';
import { AuthResponse, Tokens, UserData } from './types';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private tokenService: TokenService,
    private configService: ConfigService,
  ) {}

  async signup(dto: SignupDto): Promise<AuthResponse> {
    // Get data from dto
    const { password, repeatedPassword, email, phone } = dto;

    // Password comparison
    if (password !== repeatedPassword) {
      throw new Error('Passwords do not match');
    }

    // Hash the password
    const hashedPassword = await this.hashPassword(password);

    // Create a UUID for a future activation link
    const activationLink = uuidv4();

    // Create new user
    let newUser;
    try {
      newUser = await this.prisma.user.create({
        data: {
          email,
          phone,
          activationLink,
          password: hashedPassword,
        },
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new NotImplementedException(
            'A user with the same phone number or email already exists',
          );
        }
      }
    }

    // Create new tokens
    const tokens = await this.createTokensInTokenService(newUser.id);

    const userData: UserData = {
      id: newUser.id,
      isActive: newUser.isActive,
    };

    return { tokens, user: userData };
  }

  async login(dto: LoginDto): Promise<AuthResponse> {
    // Find user by email
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const userId: string = user.id;

    // Verify password
    const passwordMatches = await this.verifyPassword(
      dto.password,
      user.password,
    );

    // Increase failed attempts
    if (!passwordMatches) {
      const failedAttempts = user.failedAttempts + 1;
      await this.updateFailedAttempts(userId, failedAttempts);

      if (failedAttempts >= 5) {
        await this.deactivateUser(userId);
      }

      throw new ForbiddenException('Invalid password');
    }

    // Reset all invalid attempts to 0 in case of a successful login
    await this.resetFailedAttempts(userId);

    // Create new tokens
    const tokens = await this.createTokensInTokenService(userId);

    const userData: UserData = {
      id: userId,
      isActive: user.isActive,
    };

    return {
      tokens,
      user: userData,
    };
  }

  async logout(userId: string) {
    await this.tokenService.removeToken(userId);
  }

  async hashPassword(password: string) {
    const bcryptRounds = this.configService.get<string>('BCRYPT_ROUNDS');
    const rounds = parseInt(bcryptRounds, 10);
    return bcrypt.hash(password, rounds);
  }

  async verifyPassword(password, hashedPassword) {
    return bcrypt.compare(password, hashedPassword);
  }

  async updateFailedAttempts(userId: string, attempts: number) {
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        failedAttempts: attempts,
        lastFailedAttempt: new Date(),
      },
    });
  }

  async activateUser(activationLink: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        activationLink,
      },
    });

    if (!user) {
      throw new NotFoundException('Incorrect activation link');
    }

    try {
      await this.prisma.user.update({
        where: {
          id: user.id,
        },
        data: {
          isActive: true,
        },
      });
    } catch (error) {
      throw new NotImplementedException('Failed to activate user', error);
    }
  }

  async deactivateUser(userId: string) {
    try {
      await this.prisma.user.update({
        where: { id: userId },
        data: { isActive: false },
      });
    } catch (error) {
      throw new NotImplementedException('Failed to deactivate user', error);
    }
  }

  async resetFailedAttempts(userId: string) {
    try {
      await this.prisma.user.update({
        where: { id: userId },
        data: { failedAttempts: 0 },
      });
    } catch (error) {
      throw new NotImplementedException(
        'Failed to reset all invalid attempts to 0 on login',
        error,
      );
    }
  }

  private async createTokensInTokenService(userId: string): Promise<Tokens> {
    const tokens = await this.tokenService.createTokens(userId);
    await this.tokenService.updateRefreshToken(userId, tokens.refreshToken);
    return tokens;
  }
}
