export type Tokens = {
  accessToken: string;
  refreshToken: string;
};

export type UserData = {
  id: string;
  isActive: boolean;
};

export type AuthResponse = {
  tokens: Tokens;
  user: UserData;
};
