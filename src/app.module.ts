import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { PrismaService } from './prisma/prisma.service';
import { TokenModule } from './token/token.module';

@Module({
  imports: [AuthModule, TokenModule],
  providers: [PrismaService],
})
export class AppModule {}
