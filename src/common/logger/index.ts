import { Logger } from '@nestjs/common';
import { ILoggerError, ILoggerLog } from './types';

export class MyLogger extends Logger {
  error(message: ILoggerError) {
    super.error(message);
  }

  log(message: ILoggerLog) {
    super.log(message);
  }
}
