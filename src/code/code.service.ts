import { Inject, Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ClientProxy } from '@nestjs/microservices';
import { CodeType } from '@prisma/client';
import { randomInt } from 'crypto';
import { calculateEndDate } from '../common';
import { MyLogger } from '../logger/my-logger.service';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class CodeService {
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
    const codeExpires = this.configService.get<string>('CODE_EXPIRES_IN');
    const codeExpirationDate = calculateEndDate(codeExpires);

    await this.prisma.code.create({
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
    const codeFromDB = await this.prisma.code.findFirst({
      where: {
        userId,
        codeType,
      },
    });

    // Generate a new code
    const newCode: number = this.generate();

    // Create a code with expiration date
    const codeExpires = this.configService.get<string>('CODE_EXPIRES_IN');
    const newCodeExpirationDate = calculateEndDate(codeExpires);

    await this.prisma.code.update({
      where: {
        id: codeFromDB.id,
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
    codeType: CodeType,
    userId: string,
  ): Promise<void> {
    const codeFromDB = await this.prisma.code.findFirst({
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

    // Remove the codeType codes for the user as they are no longer needed
    await this.deleteMany(userId, codeType);
  }

  async resend(userId: string, codeType: CodeType): Promise<void> {
    const user = await this.prisma.user.findFirst({
      where: {
        id: userId,
      },
    });

    const code = await this.update(userId, codeType);
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
      code,
      codeType,
      id: userId,
      email: user.email,
    };

    await this.client.emit(routingKey, data);
    this.logger.log({
      method: routingKey,
      log: `routingKey event published with id: ${userId}`,
    });
  }

  async deleteMany(userId: string, codeType: CodeType): Promise<void> {
    try {
      await this.prisma.code.deleteMany({
        where: {
          userId,
          codeType,
        },
      });
    } catch (error) {
      this.logger.error({
        method: 'code-delete',
        error,
      });
    }
  }
}
