import {
  Body,
  Controller,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  Post,
  Res,
} from '@nestjs/common';
import { Response } from 'express';
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
  async register(
    @Body() registerDto: RegisterDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      const user = await this.userService.register(registerDto);
      const token = await this.jwtService.createToken(user);
      response.cookie('token', token, {
        httpOnly: true,
        path: '/',
        maxAge: 3600000, // cookie lifetime = 1 hour
        // secure: true, // uncomment in the production environment for HTTPS
        sameSite: 'strict',
      });

      return true;
    } catch (error) {
      throw new ForbiddenException('Error during registration', error.message);
    }
  }
}
