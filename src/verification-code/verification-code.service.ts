import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ClientProxy } from '@nestjs/microservices';
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
    @Inject('AUTH_CLIENT') private readonly client: ClientProxy,
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

  async update(userId: string, codeType: CodeType): Promise<number> {
    const verificationCodeFromDB = await this.prisma.verificationCode.findFirst(
      {
        where: {
          userId,
          codeType,
        },
      },
    );

    // Generate a new code
    const newCode: number = this.generate();

    // Create a code with expiration date
    const codeExpires = this.configService.get<string>(
      'VERIFICATION_CODE_EXPIRES_IN',
    );
    const newCodeExpirationDate = calculateEndDate(codeExpires);

    await this.prisma.verificationCode.update({
      where: {
        id: verificationCodeFromDB.id,
      },
      data: {
        code: newCode,
        expiresAt: newCodeExpirationDate,
      },
    });

    return newCode;
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

  async resend(userId: string, codeType: CodeType): Promise<void> {
    const user = await this.prisma.user.findFirst({
      where: {
        id: userId,
      },
    });

    const verificationCode = await this.update(userId, codeType);
    let routingKey;
    switch (codeType) {
      case CodeType.EMAIL_CONFIRMATION:
        routingKey = 'email_confirmation_code_resended';
        break;
      case CodeType.PHONE_CONFIRMATION:
        routingKey = 'phone_confirmation_code_resended';
        break;
      default:
        routingKey = '';
    }

    const data = {
      id: userId,
      email: user.email,
      ...(codeType === CodeType.EMAIL_CONFIRMATION && {
        verificationCodeEmail: verificationCode,
      }),
    };

    await this.client.emit(routingKey, data);
    this.logger.log({
      method: routingKey,
      log: `routingKey event published with id: ${userId}`,
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
