import { Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CodeType } from '@prisma/client';
import { randomInt } from 'crypto';
import { calculateEndDate } from '../common';
import { MyLogger } from '../logger/my-logger.service';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class VerificationCodeService {
  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
    private readonly logger: MyLogger,
  ) {}

  generate(): number {
    return randomInt(100000, 1000000); // 6 digits
  }

  async create(userId: string, codeType: CodeType): Promise<number> {
    // Generate a code
    const code: number = this.generate();

    // Create a code with expiration date
    const codeExpires = this.configService.get<string>(
      'VERIFICATION_CODE_EXPIRES_IN',
    );
    const codeExpirationDate = calculateEndDate(codeExpires);

    await this.prisma.verificationCode.create({
      data: {
        userId,
        code,
        codeType,
        expiresAt: codeExpirationDate,
      },
    });

    return code;
  }

  async verify(
    code: number,
    userId: string | undefined,
    codeType: CodeType,
  ): Promise<void> {
    await this.prisma.$transaction(async (prisma) => {
      const codeFromDB = await prisma.verificationCode.findFirst({
        where: {
          userId,
          code,
          codeType,
          expiresAt: {
            gte: new Date(),
          },
        },
      });

      if (!codeFromDB) {
        throw new NotFoundException('Invalid code');
      }

      // Delete the code as it will no longer be needed
      await this.delete(codeFromDB.id);
    });
  }

  async delete(codeId: string): Promise<void> {
    try {
      await this.prisma.verificationCode.delete({
        where: {
          id: codeId,
        },
      });
    } catch (error) {
      this.logger.error({
        method: 'verification-code-delete',
        error,
      });
    }
  }
}
