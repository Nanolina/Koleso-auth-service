import { Logger } from '@nestjs/common';
import { ILoggerError } from './types';

export class LoggerError extends Logger {
  error(message: ILoggerError) {
    super.error(message);
  }
}
