import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { AtStrategy, RtStrategy } from './strategies';
import { TokenService } from './token.service';

@Module({
  imports: [JwtModule.register({})],
  providers: [TokenService, PrismaService, AtStrategy, RtStrategy],
  exports: [TokenService],
})
export class TokenModule {}
