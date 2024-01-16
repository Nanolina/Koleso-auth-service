import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  NotImplementedException,
  UnauthorizedException,
} from '@nestjs/common';
import { JsonWebTokenError, JwtService } from '@nestjs/jwt';
import { createHash } from 'crypto';
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

  hashToken(token: string) {
    return createHash('sha256').update(token).digest('hex');
  }

  async isRefreshTokenMatches(token, hashedToken) {
    const refreshTokenMatches = (await this.hashToken(token)) === hashedToken;

    if (!refreshTokenMatches) {
      throw new ForbiddenException("The tokens don't match");
    }

    return true;
  }

  async validateRefreshToken(token: string) {
    try {
      return this.jwtService.verifyAsync(token, {
        secret: process.env.JWT_REFRESH_SECRET,
      });
    } catch (error) {
      return null;
    }
  }

  async findToken(userId: string, refreshToken: string) {
    // Find token by user ID
    const tokenData = await this.prisma.token.findFirst({
      where: {
        userId,
      },
    });

    if (!tokenData) {
      throw new NotFoundException('Token not found by userId');
    }

    if (!tokenData.token) {
      throw new UnauthorizedException('Token is null');
    }

    // Check if JWT refresh token in the cookie and in the database are equal
    await this.isRefreshTokenMatches(refreshToken, tokenData.token);

    return tokenData;
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    // Hash token
    const hashedToken = await this.hashToken(refreshToken);

    // Update refreshToken in the DB
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

  async createTokens(userId: string): Promise<Tokens> {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          id: userId,
        },
        {
          secret: process.env.JWT_ACCESS_SECRET,
          expiresIn: process.env.JWT_ACCESS_EXPIRES_IN,
        },
      ),
      this.jwtService.signAsync(
        {
          id: userId,
        },
        {
          secret: process.env.JWT_REFRESH_SECRET,
          expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
        },
      ),
    ]);

    return {
      accessToken: accessToken,
      refreshToken: refreshToken,
    };
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const userData = await this.validateRefreshToken(refreshToken);

    // Find token by user ID
    const tokenFromDB = await this.findToken(userId, refreshToken);

    if (!userData || !tokenFromDB) {
      throw new UnauthorizedException('Failed to refresh the token');
    }

    // Create new tokens
    const tokens = await this.createTokens(userId);

    // Update refresh token in the DB
    await this.updateRefreshToken(userId, tokens.refreshToken);

    return tokens;
  }

  async removeToken(refreshToken: string, userId: string) {
    // Find token by user ID
    await this.findToken(userId, refreshToken);

    // Delete token by user ID
    try {
      await this.prisma.token.delete({
        where: {
          userId,
        },
      });
    } catch (error) {
      throw new NotImplementedException('Failed to delete the token', error);
    }
  }
}
