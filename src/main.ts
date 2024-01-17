import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import * as cookieParser from 'cookie-parser';
import * as cors from 'cors';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Config
  const configService = app.get(ConfigService);

  // Cors
  app.use(
    cors({
      origin: configService.get<string>('SELLER_INTERFACE_URL'),
      credentials: true,
    }),
  );

  // Validation
  app.useGlobalPipes(new ValidationPipe());

  // Cookie
  app.use(cookieParser());

  await app.listen(3000);
}
bootstrap();
