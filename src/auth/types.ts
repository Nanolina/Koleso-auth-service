import { RoleType } from '@prisma/client';

export type Tokens = {
  accessToken: string;
  refreshToken: string;
};

export interface UserDataSetNewPassword {
  isActive: boolean;
}

export interface UserData extends UserDataSetNewPassword {
  id: string;
  email: string;
  phone: string;
  role: RoleType;
  isVerifiedEmail: boolean;
}

export type AuthResponse = {
  tokens: Tokens;
  user: UserData;
};

export type ChangeEmailResponse = {
  email: string;
  isVerifiedEmail: boolean;
};

export type EmailResponse = {
  email: string;
};
