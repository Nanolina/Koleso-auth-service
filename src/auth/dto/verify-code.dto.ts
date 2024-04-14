import { IsDefined, IsEmail, Validate } from 'class-validator';
import { IsValidCodeConstraint } from '../validators';

export class VerifyCodeDto {
  @IsDefined()
  @Validate(IsValidCodeConstraint)
  code: number;

  @IsDefined()
  @IsEmail()
  email: string;
}
