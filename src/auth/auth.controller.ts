import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import * as dotenv from 'dotenv';
import { Request, Response } from 'express';
import { Public } from '../common/decorators';
import { RtGuard } from '../common/guards';
import { TokenService } from '../token/token.service';
import { AuthService } from './auth.service';
import { LoginDto, SignUpDto } from './dto';
import { Tokens } from './types';

dotenv.config();

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private tokenService: TokenService,
  ) {}

  @Public()
  @Post('/signup')
  @HttpCode(HttpStatus.CREATED)
  async signup(
    @Body() dto: SignUpDto,
    @Res() res: Response,
  ): Promise<Response> {
    const tokens = await this.authService.signUp(dto);

    // Send cookie
    const cookieExpiresInterval = parseInt(process.env.COOKIE_EXPIRES, 10);

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      expires: new Date(Date.now() + cookieExpiresInterval),
      // secure: true,
      sameSite: 'strict',
    });

    return res.send({ message: 'User created successfully' });
  }

  @Public()
  @Post('/login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginDto): Promise<Tokens> {
    return this.authService.login(dto);
  }

  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request) {
    const user = req.user;
    return this.authService.logout(user.sub);
  }

  @Public()
  @UseGuards(RtGuard)
  @Get('/refresh')
  @HttpCode(HttpStatus.OK)
  async refreshTokens(@Req() req: Request) {
    const user = req.user;
    return this.tokenService.refreshTokens(user.sub, user.refreshToken);
  }

  @Public()
  @Get('/activate/:activationLink')
  @HttpCode(HttpStatus.OK)
  async activateLink(
    @Param('activationLink') activationLink: string,
    @Res() res: Response,
  ) {
    await this.authService.activateUser(activationLink);

    res.redirect(process.env.SELLER_INTERFACE_URL);
  }
}
