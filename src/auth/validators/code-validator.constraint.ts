import {
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';

@ValidatorConstraint({ name: 'isValidCode', async: false })
export class IsValidCodeConstraint implements ValidatorConstraintInterface {
  validate(value: any) {
    return typeof value === 'number' && /^[0-9]{6}$/.test(value.toString());
  }

  defaultMessage() {
    return 'The code must consist of exactly 6 digits';
  }
}
