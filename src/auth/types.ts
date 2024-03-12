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
  activationLinkId: string;
  isVerifiedEmail: boolean;
}

export type AuthResponse = {
  tokens: Tokens;
  user: UserData;
};
