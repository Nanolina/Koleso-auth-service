import { Module } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterController } from './register.controller';
import { RegisterService } from './register.service';

@Module({
  controllers: [RegisterController],
  providers: [RegisterService, PrismaService],
})
export class RegisterModule {}
