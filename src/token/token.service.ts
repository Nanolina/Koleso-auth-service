import {
  Injectable,
  NotFoundException,
  NotImplementedException,
  UnauthorizedException,
} from '@nestjs/common';
import { JsonWebTokenError, JwtService } from '@nestjs/jwt';
import { createHash } from 'crypto';
import * as dotenv from 'dotenv';
import { Tokens, UserData } from '../auth';
import { PrismaService } from '../prisma/prisma.service';
import { calculateEndDate } from './functions';
import { JWTInfo } from './types';

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
    const result: boolean = (await this.hashToken(token)) === hashedToken;
    return result;
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

    if (!tokenData || !tokenData.token) {
      throw new NotFoundException(
        'Token data not found by userId or token is empty',
      );
    }

    // Check if JWT refresh token in the cookie and in the database are equal
    const isTokenMatches = await this.isRefreshTokenMatches(
      refreshToken,
      tokenData.token,
    );

    if (!isTokenMatches) {
      throw new UnauthorizedException('The tokens do not match');
    }

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

  async refreshTokens(refreshToken: string) {
    const tokenInfo: JWTInfo = await this.validateRefreshToken(refreshToken);

    // Find user by his ID
    const user = await this.prisma.user.findFirst({
      where: {
        id: tokenInfo.id || '',
      },
    });

    if (!user) {
      throw new NotFoundException('User not found when refresh');
    }

    const userId: string = user.id;

    // Check if this user has this token in the DB
    const tokenFromDB = await this.findToken(userId, refreshToken);

    if (!tokenFromDB) {
      throw new UnauthorizedException('Something went wrong with the refresh');
    }

    // Create new tokens
    const tokens = await this.createTokens(userId);

    // Update refresh token in the DB
    await this.updateRefreshToken(userId, tokens.refreshToken);

    const userData: UserData = {
      id: userId,
      isActive: user.isActive,
    };

    return { tokens, user: userData };
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
