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

  verifyToken(token, hashedToken) {
    return this.hashToken(token) === hashedToken;
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
    // Find user by his ID
    const user = await this.prisma.user.findFirst({
      where: {
        id: userId,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found by his ID');
    }

    // Find token by user ID
    const token = await this.prisma.token.findFirst({
      where: {
        userId,
      },
    });

    if (!token) {
      throw new NotFoundException('Token not found by userId');
    }

    if (!token.token) {
      throw new UnauthorizedException('Token is null');
    }

    // Verify refresh token
    const refreshTokenMatches = await this.verifyToken(
      refreshToken,
      token.token,
    );

    if (!refreshTokenMatches) {
      throw new ForbiddenException("The tokens don't match");
    }

    // Create new tokens
    const tokens = await this.createTokens(user.id);

    // Update refresh token in the DB
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  async removeToken(refreshToken: string, userId: string) {
    // Find token by user ID
    const tokenData = await this.prisma.token.findFirst({
      where: {
        userId,
      },
    });

    if (!tokenData) {
      throw new NotFoundException('Failed to find the token when deleting it');
    }

    // Verify refresh token
    const refreshTokenMatches = await this.verifyToken(
      refreshToken,
      tokenData.token,
    );

    if (!refreshTokenMatches) {
      throw new ForbiddenException("The tokens don't match");
    }

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
