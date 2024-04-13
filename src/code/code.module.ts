import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { LoggerModule } from '../logger/logger.module';
import { PrismaService } from '../prisma/prisma.service';
import { CodeService } from './code.service';

@Module({
  imports: [
    LoggerModule,
    ClientsModule.registerAsync([
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
  providers: [CodeService, PrismaService],
  exports: [CodeService],
})
export class CodeModule {}
