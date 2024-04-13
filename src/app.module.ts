import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { AuthModule } from './auth/auth.module';
import { CodeModule } from './code/code.module';
import { AtGuard } from './common/guards';
import { PrismaService } from './prisma/prisma.service';
import { RabbitMQModule } from './rabbitmq/rabbitmq.module';
import { TokenModule } from './token/token.module';

@Module({
  imports: [
    AuthModule,
    TokenModule,
    CodeModule,
    RabbitMQModule,
    ConfigModule.forRoot({
      isGlobal: true,
    }),
  ],
  providers: [
    PrismaService,
    {
      provide: APP_GUARD,
      useClass: AtGuard,
    },
  ],
})
export class AppModule {}
