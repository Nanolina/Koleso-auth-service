import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaService } from './prisma/prisma.service';
import { RegisterModule } from './register/register.module';

@Module({
  imports: [RegisterModule],
  controllers: [AppController],
  providers: [AppService, PrismaService],
})
export class AppModule {}
