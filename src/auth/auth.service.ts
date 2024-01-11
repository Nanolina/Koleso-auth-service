import { ForbiddenException, Injectable } from '@nestjs/common';
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
    const { password, repeatedPassword, email, phone } = dto;

    // Password comparison
    if (password !== repeatedPassword) {
      throw new Error('Passwords do not match');
    }

    // Hash the password
    const hashedPassword = await this.tokenService.hashData(password);

    const newUser = await this.prisma.user.create({
      data: {
        email,
        phone,
        password: hashedPassword,
      },
    });

    const tokens = await this.tokenService.getTokens(newUser.id);

    await this.tokenService.createRefreshToken(
      newUser.id,
      tokens.refresh_token,
    );
    return tokens;
  }

  async login(dto: LoginDto): Promise<Tokens> {
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('User not found');
    }

    const passwordMatches = await this.tokenService.verifyHashedData(
      dto.password,
      user.password,
    );

    if (!passwordMatches) {
      await this.prisma.user.update({
        where: {
          id: user.id,
        },
        data: {
          failedAttempts: {
            increment: 1,
          },
          lastFailedAttempt: new Date(),
        },
      });

      if (user.failedAttempts >= 5) {
        await this.prisma.user.update({
          where: {
            id: user.id,
          },
          data: {
            isActive: false,
          },
        });
      }

      throw new ForbiddenException('Invalid password');
    }

    const tokens = await this.tokenService.getTokens(user.id);

    await this.tokenService.updateRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: string) {
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
}
