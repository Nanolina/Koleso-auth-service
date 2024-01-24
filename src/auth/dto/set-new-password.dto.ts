import { IsString, IsUUID, MinLength } from 'class-validator';

export class SetNewPasswordDto {
  @IsString()
  @MinLength(8)
  password: string;

  @IsString()
  @MinLength(8)
  repeatedPassword: string;
}

export class SetNewPasswordServiceDto extends SetNewPasswordDto {
  @IsUUID()
  userId: string;
}
