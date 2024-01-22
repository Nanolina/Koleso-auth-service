import { NotImplementedException } from '@nestjs/common';
import { addDays, addHours, addMinutes, addSeconds, addWeeks } from 'date-fns';
import { UNKNOWN_ERROR, convertToNumber } from '../common';
import { MyLogger } from '../logger/my-logger.service';

// See the .env file to change the token expires in - interval type
export function calculateEndDate(interval: string): Date {
  const logger = new MyLogger('calculateEndDate');

  const currentDate = new Date();
  const intervalType = interval.slice(-1);
  const intervalNumber = convertToNumber(interval.slice(0, -1));

  switch (intervalType) {
    case 's':
      return addSeconds(currentDate, intervalNumber);
    case 'm':
      return addMinutes(currentDate, intervalNumber);
    case 'h':
      return addHours(currentDate, intervalNumber);
    case 'd':
      return addDays(currentDate, intervalNumber);
    case 'w':
      return addWeeks(currentDate, intervalNumber);
    default:
      logger.error({
        method: 'calculateEndDate',
        error: 'Invalid interval type, please check .env',
      });

      throw new NotImplementedException(UNKNOWN_ERROR);
  }
}
