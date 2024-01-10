import {
  Body,
  Controller,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import { JWTService } from '../jwt/jwt.service';
import { RegisterDto } from './register.dto';
import { UserService } from './user.service';

@Controller('auth')
export class UserController {
  constructor(
    private userService: UserService,
    private jwtService: JWTService,
  ) {}

  @Post('/register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto) {
    try {
      const user = await this.userService.register(registerDto);
      const token = await this.jwtService.createToken(user);
      return { token };
    } catch (error) {
      throw new ForbiddenException('Error during registration');
    }
  }
}
