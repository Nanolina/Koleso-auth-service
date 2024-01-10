import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { JWTModule } from './jwt/jwt.module';
import { PrismaService } from './prisma/prisma.service';
import { UserModule } from './user/user.module';

@Module({
  imports: [UserModule, JWTModule],
  controllers: [AppController],
  providers: [AppService, PrismaService],
})
export class AppModule {}
