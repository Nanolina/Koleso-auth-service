import {
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { createHash } from 'crypto';
import { Tokens, UserData } from '../auth';
import { UNKNOWN_ERROR, UNKNOWN_ERROR_TRY } from '../common';
import { MyLogger } from '../common/logger';
import { PrismaService } from '../prisma/prisma.service';
import { calculateEndDate } from './functions';
import { JWTInfo } from './types';

@Injectable()
export class TokenService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  private readonly logger = new MyLogger(TokenService.name);

  hashToken(token: string) {
    return createHash('sha256').update(token).digest('hex');
  }

  // Check if refresh token in the cookie and in the database are equal
  private isRefreshTokenMatches(token, hashedToken) {
    const result: boolean = this.hashToken(token) === hashedToken;
    if (!result) {
      this.logger.error({
        method: 'isRefreshTokenMatches',
        error: 'The tokens do not match',
      });

      throw new UnauthorizedException(UNKNOWN_ERROR);
    }

    return result;
  }

  async validateRefreshToken(token: string) {
    try {
      return await this.jwtService.verifyAsync(token, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });
    } catch (error) {
      this.logger.error({ method: 'validateRefreshToken', error });

      return null;
    }
  }

  async findToken(userId: string) {
    // Find token by user ID
    const tokenFromDB = await this.prisma.token.findFirst({
      where: {
        userId,
      },
    });

    if (!tokenFromDB || !tokenFromDB.token) {
      this.logger.error({
        method: 'findToken',
        error: 'Token not found',
      });

      throw new UnauthorizedException(UNKNOWN_ERROR);
    }

    return tokenFromDB;
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    // Hash token
    const hashedToken = this.hashToken(refreshToken);

    // CONFIG
    const refreshExpires = this.configService.get<string>(
      'JWT_REFRESH_EXPIRES_IN',
    );
    const tokenExpirationDate = calculateEndDate(refreshExpires);

    // Update refreshToken in the DB
    try {
      await this.prisma.token.upsert({
        where: {
          userId,
        },
        create: {
          token: hashedToken,
          expiresAt: tokenExpirationDate,
          userId,
        },
        update: {
          token: hashedToken,
          expiresAt: tokenExpirationDate,
        },
      });
    } catch (error) {
      this.logger.error({ method: 'updateRefreshToken', error });

      throw new InternalServerErrorException(UNKNOWN_ERROR);
    }
  }

  async createTokens(userId: string): Promise<Tokens> {
    try {
      // CONFIG
      // Access
      const accessTokenSecret =
        this.configService.get<string>('JWT_ACCESS_SECRET');
      const accessTokenExpires = this.configService.get<string>(
        'JWT_ACCESS_EXPIRES_IN',
      );

      // Refresh
      const refreshTokenSecret =
        this.configService.get<string>('JWT_REFRESH_SECRET');
      const refreshTokenExpires = this.configService.get<string>(
        'JWT_REFRESH_EXPIRES_IN',
      );

      const [accessToken, refreshToken] = await Promise.all([
        this.jwtService.signAsync(
          {
            id: userId,
          },
          {
            secret: accessTokenSecret,
            expiresIn: accessTokenExpires,
          },
        ),
        this.jwtService.signAsync(
          {
            id: userId,
          },
          {
            secret: refreshTokenSecret,
            expiresIn: refreshTokenExpires,
          },
        ),
      ]);

      return {
        accessToken: accessToken,
        refreshToken: refreshToken,
      };
    } catch (error) {
      this.logger.error({ method: 'createTokens', error });

      throw new InternalServerErrorException(UNKNOWN_ERROR);
    }
  }

  async refreshTokens(refreshToken: string) {
    const tokenInfo: JWTInfo = await this.validateRefreshToken(refreshToken);

    if (!tokenInfo) {
      this.logger.error({
        method: 'refreshTokens',
        error: 'Failed to validate refresh token',
      });

      throw new UnauthorizedException(UNKNOWN_ERROR);
    }

    // Find user by his ID
    const user = await this.prisma.user.findFirst({
      where: {
        id: tokenInfo.id || '',
      },
    });

    if (!user) {
      this.logger.error({
        method: 'refreshTokens',
        error: 'User not found with token',
      });

      throw new UnauthorizedException(UNKNOWN_ERROR);
    }

    const userId: string = user.id;

    /**
     * Check if this user has this token in the DB
     * If the token is not found or is empty,
     * the method will throw an error
     */
    const tokenFromDB = await this.findToken(userId);

    /**
     * Check if refresh token in the cookie and in the database are equal
     * If the tokens are not equal,
     * the method will throw an error
     * */
    this.isRefreshTokenMatches(refreshToken, tokenFromDB.token);

    // Create new tokens
    const tokens = await this.createTokens(userId);

    // Update refresh token in the DB
    await this.updateRefreshToken(userId, tokens.refreshToken);

    const userData: UserData = {
      id: userId,
      isActive: user.isActive,
    };

    return {
      tokens,
      user: userData,
    };
  }

  async removeToken(userId: string) {
    try {
      await this.prisma.token.delete({
        where: {
          userId,
        },
      });
    } catch (error) {
      this.logger.error({ method: 'removeToken', error });

      throw new InternalServerErrorException(UNKNOWN_ERROR_TRY);
    }
  }
}
