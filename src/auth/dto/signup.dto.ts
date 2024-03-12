import { RoleType } from '@prisma/client';
import {
  IsDefined,
  IsEmail,
  IsString,
  MinLength,
  Validate,
} from 'class-validator';
import { IsValidRoleConstraint } from '../validators';

export class SignupDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(10)
  phone: string;

  @IsString()
  @MinLength(8)
  password: string;

  @IsString()
  @MinLength(8)
  repeatedPassword: string;

  @IsDefined()
  @Validate(IsValidRoleConstraint)
  role: RoleType;
}
