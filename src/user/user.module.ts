import { Module } from '@nestjs/common';
import { JWTModule } from '../jwt/jwt.module';
import { PrismaService } from '../prisma/prisma.service';
import { UserController } from './user.controller';
import { UserService } from './user.service';

@Module({
  imports: [JWTModule],
  controllers: [UserController],
  providers: [UserService, PrismaService],
})
export class UserModule {}
