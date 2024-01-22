import { IsEmail, IsUUID } from 'class-validator';

export class ChangeEmailDto {
  @IsEmail()
  email: string;
}

export class ChangeEmailServiceDto extends ChangeEmailDto {
  @IsUUID()
  id: string;
}
