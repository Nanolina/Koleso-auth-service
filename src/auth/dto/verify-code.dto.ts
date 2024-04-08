import { CodeType } from '@prisma/client';
import { IsDefined, Validate } from 'class-validator';
import {
  IsValidCodeTypeConstraint,
  IsValidVerificationCodeConstraint,
} from '../validators';

export class VerifyCodeDto {
  @IsDefined()
  @Validate(IsValidVerificationCodeConstraint)
  code: number;

  @IsDefined()
  @Validate(IsValidCodeTypeConstraint)
  codeType: CodeType;
}
