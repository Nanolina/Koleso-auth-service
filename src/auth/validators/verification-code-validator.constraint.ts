import {
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

@ValidatorConstraint({ name: 'isValidVerificationCode', async: false })
export class IsValidVerificationCodeConstraint
  implements ValidatorConstraintInterface
{
  validate(value: any) {
    return typeof value === 'number' && /^[0-9]{6}$/.test(value.toString());
  }

  defaultMessage() {
    return 'The verification code must consist of exactly 6 digits';
  }
}
