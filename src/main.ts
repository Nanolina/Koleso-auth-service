import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import * as cors from 'cors';
import * as dotenv from 'dotenv';
import * as cookieParser from 'cookie-parser';
import { AppModule } from './app.module';

dotenv.config();

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Cors
  app.use(
    cors({
      origin: process.env.SELLER_INTERFACE_URL,
    }),
  );

  // Validation
  app.useGlobalPipes(new ValidationPipe());

  // Cookie
  app.use(cookieParser());

  await app.listen(3000);
}
bootstrap();
