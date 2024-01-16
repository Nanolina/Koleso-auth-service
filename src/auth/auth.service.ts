import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  NotImplementedException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import * as dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';
import { PrismaService } from '../prisma/prisma.service';
import { TokenService } from '../token/token.service';
import { LoginDto, SignUpDto } from './dto';
import { Tokens } from './types';

dotenv.config();

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private tokenService: TokenService,
  ) {}

  async signUp(dto: SignUpDto): Promise<Tokens> {
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
    const tokens = await this.tokenService.createTokens(newUser.id);

    // Update refreshToken in the DB
    await this.tokenService.updateRefreshToken(newUser.id, tokens.refreshToken);

    return tokens;
  }

  async login(dto: LoginDto): Promise<Tokens> {
    // Find user by email
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify password
    const passwordMatches = await this.verifyPassword(
      dto.password,
      user.password,
    );

    // Increase failed attempts
    if (!passwordMatches) {
      const failedAttempts = user.failedAttempts + 1;
      await this.updateFailedAttempts(user.id, failedAttempts);

      if (failedAttempts >= 5) {
        await this.deactivateUser(user.id);
      }

      throw new ForbiddenException('Invalid password');
    }

    // Reset all invalid attempts to 0 in case of a successful login
    await this.resetFailedAttempts(user.id);

    // Create new tokens
    const tokens = await this.tokenService.createTokens(user.id);

    // Update refreshToken in the DB
    await this.tokenService.updateRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  async logout(refreshToken: string, userId: string) {
    await this.tokenService.removeToken(refreshToken, userId);
  }

  async hashPassword(password: string) {
    const rounds = parseInt(process.env.BCRYPT_ROUNDS, 10);
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
}
