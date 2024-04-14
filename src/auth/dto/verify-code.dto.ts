import { IsDefined, Validate } from 'class-validator';
import { IsValidCodeConstraint } from '../validators';

export class VerifyCodeDto {
  @IsDefined()
  @Validate(IsValidCodeConstraint)
  code: number;
}
