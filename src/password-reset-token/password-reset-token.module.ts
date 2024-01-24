import { Module } from '@nestjs/common';
import { LoggerModule } from '../logger/logger.module';
import { PrismaService } from '../prisma/prisma.service';
import { PasswordResetTokenService } from './password-reset-token.service';

@Module({
  imports: [LoggerModule],
  providers: [PasswordResetTokenService, PrismaService],
  exports: [PasswordResetTokenService],
})
export class PasswordResetTokenModule {}
