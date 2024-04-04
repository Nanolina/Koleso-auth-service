import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { AuthModule } from './auth/auth.module';
import { AtGuard } from './common/guards';
import { PasswordResetTokenModule } from './password-reset-token/password-reset-token.module';
import { PrismaService } from './prisma/prisma.service';
import { RabbitMQModule } from './rabbitmq/rabbitmq.module';
import { TokenModule } from './token/token.module';

@Module({
  imports: [
    AuthModule,
    TokenModule,
    PasswordResetTokenModule,
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
