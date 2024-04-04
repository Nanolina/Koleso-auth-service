import { Module } from '@nestjs/common';
import { LoggerModule } from '../logger/logger.module';
import { RabbitMQService } from './rabbitmq.service';

@Module({
  imports: [LoggerModule],
  providers: [RabbitMQService],
  exports: [RabbitMQService],
})
export class RabbitMQModule {}
