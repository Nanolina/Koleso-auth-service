import { RoleType } from '@prisma/client';

export type JWTInfo = {
  id: string;
  iat: number;
  exp: number;
};

export type UserData = {
  id: string;
  email: string;
  phone: string;
  isActive: boolean;
  isVerifiedEmail: boolean;
  role: RoleType;
};
