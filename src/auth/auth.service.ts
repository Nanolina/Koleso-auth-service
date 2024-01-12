import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as dotenv from 'dotenv';
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

    // Create new user
    const newUser = await this.prisma.user.create({
      data: {
        email,
        phone,
        password: hashedPassword,
      },
    });

    // Create new tokens
    const tokens = await this.tokenService.createTokens(newUser.id);

    // Update refresh_token in the DB
    await this.tokenService.updateRefreshToken(
      newUser.id,
      tokens.refresh_token,
    );

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

    // Create new tokens
    const tokens = await this.tokenService.createTokens(user.id);

    // Update refresh_token in the DB
    await this.tokenService.updateRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: string) {
    // Set token to null for user
    await this.prisma.token.updateMany({
      where: {
        userId,
        token: {
          not: null,
        },
      },
      data: {
        token: null,
      },
    });
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

  async deactivateUser(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { isActive: false },
    });
  }
}
