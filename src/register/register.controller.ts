// auth.controller.ts
import { Body, Controller, HttpStatus, Post, Res } from '@nestjs/common';
import { Response } from 'express';
import { RegisterDto } from './register.dto';
import { RegisterService } from './register.service';

@Controller('auth')
export class RegisterController {
  constructor(private registerService: RegisterService) {}

  @Post('/register')
  async register(@Body() registerDto: RegisterDto, @Res() response: Response) {
    try {
      await this.registerService.register(registerDto);
      return response.status(HttpStatus.OK).send();
    } catch (error) {
      return response
        .status(HttpStatus.BAD_REQUEST)
        .json({ message: error.message });
    }
  }
}
