import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AtStrategy, RtStrategy } from '../common/strategies';
import { LoggerModule } from '../logger/logger.module';
import { PrismaService } from '../prisma/prisma.service';
import { TokenService } from './token.service';

@Module({
  imports: [JwtModule.register({}), LoggerModule],
  providers: [TokenService, PrismaService, AtStrategy, RtStrategy],
  exports: [TokenService],
})
export class TokenModule {}
