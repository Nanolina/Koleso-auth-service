import { ForbiddenException, Injectable } from '@nestjs/common';
import { JsonWebTokenError, JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as dotenv from 'dotenv';
import { Tokens } from '../auth/types';
import { PrismaService } from '../prisma/prisma.service';
import { calculateEndDate } from './functions';

dotenv.config();

@Injectable()
export class TokenService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  hashData(data: any) {
    return bcrypt.hash(data, 10);
  }

  verifyHashedData(externalData, dataDB) {
    return bcrypt.compare(externalData, dataDB);
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedToken = await this.hashData(refreshToken);

    try {
      await this.prisma.token.upsert({
        where: {
          userId,
        },
        create: {
          token: hashedToken,
          expiresAt: calculateEndDate(process.env.JWT_REFRESH_EXPIRES_IN),
          userId,
        },
        update: {
          token: hashedToken,
          expiresAt: calculateEndDate(process.env.JWT_REFRESH_EXPIRES_IN),
        },
      });
    } catch (error) {
      throw new JsonWebTokenError('Failed to update the refresh token', error);
    }
  }

  async getTokens(userId: string): Promise<Tokens> {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
        },
        {
          secret: process.env.JWT_ACCESS_SECRET,
          expiresIn: process.env.JWT_ACCESS_EXPIRES_IN,
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
        },
        {
          secret: process.env.JWT_REFRESH_SECRET,
          expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
        },
      ),
    ]);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        id: userId,
      },
    });

    if (!user) {
      throw new ForbiddenException('User not found by his ID');
    }

    const token = await this.prisma.token.findFirst({
      where: {
        userId,
      },
    });

    const refreshTokenMatches = await this.verifyHashedData(
      refreshToken,
      token.token,
    );

    if (!refreshTokenMatches) {
      throw new ForbiddenException("The tokens don't match");
    }

    const tokens = await this.getTokens(user.id);

    await this.updateRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }
}
