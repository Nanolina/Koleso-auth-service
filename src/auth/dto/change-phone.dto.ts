import { IsString, IsUUID, MinLength } from 'class-validator';

export class ChangePhoneDto {
  @IsString()
  @MinLength(10)
  phone: string;
}

export class ChangePhoneServiceDto extends ChangePhoneDto {
  @IsUUID()
  id: string;
}
