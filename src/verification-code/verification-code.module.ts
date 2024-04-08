import { Module } from '@nestjs/common';
import { LoggerModule } from '../logger/logger.module';
import { PrismaService } from '../prisma/prisma.service';
import { VerificationCodeService } from './verification-code.service';

@Module({
  imports: [LoggerModule],
  providers: [VerificationCodeService, PrismaService],
  exports: [VerificationCodeService],
})
export class VerificationCodeModule {}
