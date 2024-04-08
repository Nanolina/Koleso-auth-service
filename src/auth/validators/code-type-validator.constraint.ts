import { CodeType } from '@prisma/client';
import {
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

@ValidatorConstraint({ name: 'isValidCodeType', async: false })
export class IsValidCodeTypeConstraint implements ValidatorConstraintInterface {
  validate(code: any) {
    const codeValues = Object.values(CodeType) as string[];
    return typeof code === 'string' && codeValues.includes(code);
  }

  defaultMessage() {
    return 'The code type is incorrect';
  }
}
