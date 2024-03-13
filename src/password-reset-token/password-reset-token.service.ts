import { Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'crypto';
import { calculateEndDate } from '../common';
import { MyLogger } from '../logger/my-logger.service';
import { PrismaService } from '../prisma/prisma.service';
import { CreateResponse } from './types';

@Injectable()
export class PasswordResetTokenService {
  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
    private readonly logger: MyLogger,
  ) {}

  generate(): string {
    return randomBytes(20).toString('hex');
  }

  async create(userId: string): Promise<CreateResponse> {
    // Generate a token
    const token = this.generate();

    // Create a token with expiration date
    const tokenExpires = this.configService.get<string>(
      'PASSWORD_RESET_TOKEN_EXPIRES_IN',
    );
    const tokenExpirationDate = calculateEndDate(tokenExpires);

    await this.prisma.passwordResetToken.create({
      data: {
        userId,
        token,
        expiresAt: tokenExpirationDate,
      },
    });

    return {
      passwordResetToken: token,
    };
  }

  async verifyAndDelete(token: string, userId: string): Promise<void> {
    // Verify
    const tokenFromDB = await this.prisma.passwordResetToken.findFirst({
      where: {
        token,
        expiresAt: {
          gte: new Date(),
        },
      },
    });

    if (!tokenFromDB) {
      throw new NotFoundException('Invalid password reset link');
    }

    // Delete many tokens by userId
    await this.delete(userId);
  }

  async delete(userId: string): Promise<void> {
    try {
      await this.prisma.passwordResetToken.deleteMany({
        where: {
          userId,
        },
      });
    } catch (error) {
      this.logger.error({
        method: 'delete (password-reset-token)',
        error,
      });
    }
  }
}
