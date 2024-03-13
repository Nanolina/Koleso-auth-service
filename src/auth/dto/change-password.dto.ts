import { IsString, IsUUID, MinLength } from 'class-validator';

export class ChangePasswordDto {
  @IsString()
  @MinLength(8)
  currentPassword: string;

  @IsString()
  @MinLength(8)
  newPassword: string;

  @IsString()
  @MinLength(8)
  repeatedPassword: string;
}

export class ChangePasswordServiceDto extends ChangePasswordDto {
  @IsUUID()
  id: string;
}
