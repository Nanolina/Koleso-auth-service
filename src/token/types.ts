export type JWTInfo = {
  id: string;
  iat: number;
  exp: number;
};

export type UserData = {
  id: string;
  email: string;
  phone: string;
  activationLinkId: string;
  isActive: boolean;
  isVerifiedEmail: boolean;
  roles: string[];
};
