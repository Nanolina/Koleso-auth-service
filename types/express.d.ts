// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { Request } from 'express';

declare global {
  namespace Express {
    interface User {
      id: string;
    }

    interface Request {
      user: any;
    }
  }
}
