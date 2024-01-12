import { addDays, addMonths, addWeeks } from 'date-fns';

// See the .env file to change the token run interval
export function calculateEndDate(interval: string): Date {
  const currentDate = new Date();
  const intervalType = interval.slice(-1);
  const intervalNumber = parseInt(interval.slice(0, -1));

  switch (intervalType) {
    case 'd':
      return addDays(currentDate, intervalNumber);
    case 'w':
      return addWeeks(currentDate, intervalNumber);
    case 'm':
      return addMonths(currentDate, intervalNumber);
    default:
      throw new Error('Invalid interval type');
  }
}
