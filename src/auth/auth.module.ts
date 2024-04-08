import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { VerificationCodeModule } from 'src/verification-code/verification-code.module';
import { LoggerModule } from '../logger/logger.module';
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
    VerificationCodeModule,
    ClientsModule.registerAsync([
      {
        name: 'AUTH_FANOUT_CLIENT',
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
      {
        name: 'AUTH_CLIENT',
        inject: [ConfigService],
        useFactory: (configService: ConfigService) => ({
          transport: Transport.RMQ,
          options: {
            urls: [configService.get<string>('RABBITMQ_URL')],
            queue: configService.get<string>('RABBITMQ_AUTH_QUEUE'),
            queueOptions: {
              durable: true,
              exclusive: false,
            },
          },
        }),
      },
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaService, RabbitMQService],
})
export class AuthModule {}
