import { IsDefined, IsEmail } from 'class-validator';

export class ResendCodeDto {
  @IsDefined()
  @IsEmail()
  email: string;
}
