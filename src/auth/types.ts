export type Tokens = {
  accessToken: string;
  refreshToken: string;
};

export type UserData = {
  id: string;
  email: string;
  activationLinkId: string;
  isActive: boolean;
  isVerifiedEmail: boolean;
};

export type AuthResponse = {
  tokens: Tokens;
  user: UserData;
};
