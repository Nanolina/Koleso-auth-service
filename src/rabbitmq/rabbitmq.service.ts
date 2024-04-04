import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as amqp from 'amqplib';
import { MyLogger } from '../logger/my-logger.service';

@Injectable()
export class RabbitMQService {
  constructor(
    private readonly configService: ConfigService,
    private readonly logger: MyLogger,
  ) {}

  async publishToExchange(
    exchangeType: 'fanout' | 'direct',
    routingKey: string,
    message: any,
    exchange: string = '',
  ) {
    const connectionUrl = this.configService.get<string>('RABBITMQ_URL');

    // Connection with RabbitMQ
    const connection = await amqp.connect(connectionUrl);
    const channel = await connection.createChannel();

    // Create exchange
    await channel.assertExchange(exchange, exchangeType, { durable: true });

    // Publish message
    channel.publish(
      exchange,
      routingKey,
      Buffer.from(
        JSON.stringify({
          ...message,
          eventType: routingKey,
        }),
      ),
    );
    this.logger.log({
      method: `publishToExchange`,
      log: `Message published to ${exchangeType} exchange ${exchange} with eventType ${routingKey}`,
    });

    // Close the connection after publishing
    setTimeout(() => {
      connection.close();
    }, 500);
  }
}
