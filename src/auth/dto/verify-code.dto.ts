import { CodeType } from '@prisma/client';
import { IsDefined, Validate } from 'class-validator';
import {
  IsValidCodeConstraint,
  IsValidCodeTypeConstraint,
} from '../validators';

export class VerifyCodeDto {
  @IsDefined()
  @Validate(IsValidCodeConstraint)
  code: number;

  @IsDefined()
  @Validate(IsValidCodeTypeConstraint)
  codeType: CodeType;
}
