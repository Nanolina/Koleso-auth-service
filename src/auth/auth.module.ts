import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { LoggerModule } from '../logger/logger.module';
import { PasswordResetTokenModule } from '../password-reset-token/password-reset-token.module';
import { PrismaService } from '../prisma/prisma.service';
import { RabbitMQService } from '../rabbitmq/rabbitmq.service';
import { TokenModule } from '../token/token.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  imports: [
    ConfigModule,
    LoggerModule,
    TokenModule,
    PasswordResetTokenModule,
    ClientsModule.registerAsync([
      {
        name: 'AUTH_CLIENT',
        inject: [ConfigService],
        useFactory: (configService: ConfigService) => ({
          transport: Transport.RMQ,
          options: {
            urls: [configService.get<string>('RABBITMQ_URL')],
            exchange: configService.get<string>('RABBITMQ_AUTH_EXCHANGE'),
            exchangeType: 'fanout',
          },
        }),
      },
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaService, RabbitMQService],
})
export class AuthModule {}
