import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { TokenService } from '../token/token.service';
import { AuthService } from './auth.service';
import { LoginDto, SignUpDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private tokenService: TokenService,
  ) {}

  @Post('/signup')
  @HttpCode(HttpStatus.CREATED)
  signup(@Body() dto: SignUpDto): Promise<Tokens> {
    return this.authService.signUp(dto);
  }

  @Post('/login')
  @HttpCode(HttpStatus.OK)
  login(@Body() dto: LoginDto): Promise<Tokens> {
    return this.authService.login(dto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  logout(@Req() req: Request) {
    const user = req.user;
    return this.authService.logout(user.sub);
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('/refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(@Req() req: Request) {
    const user = req.user;
    return this.tokenService.refreshTokens(user.sub, user.refreshToken);
  }
}
