import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  NotImplementedException,
  Param,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import * as dotenv from 'dotenv';
import { Request, Response } from 'express';
import { Public } from '../common/decorators';
import { RtGuard } from '../common/guards';
import { TokenService } from '../token/token.service';
import { AuthService } from './auth.service';
import { LoginDto, SignUpDto } from './dto';

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
    const cookieExpiresInterval = parseInt(
      process.env.COOKIE_EXPIRES_INTERVAL,
      10,
    );

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      expires: new Date(Date.now() + cookieExpiresInterval),
      // secure: true,
      sameSite: 'strict',
    });

    return res.send(tokens);
  }

  @Public()
  @Post('/login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginDto, @Res() res: Response): Promise<Response> {
    const tokens = await this.authService.login(dto);

    // Send cookie
    const cookieExpiresInterval = parseInt(
      process.env.COOKIE_EXPIRES_INTERVAL,
      10,
    );

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      expires: new Date(Date.now() + cookieExpiresInterval),
      // secure: true,
      sameSite: 'strict',
    });

    return res.send(tokens);
  }

  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request, @Res() res: Response) {
    const { refreshToken } = req.cookies;
    const { id } = req.user;

    if (!refreshToken || !id) {
      throw new NotImplementedException('Failed to log out');
    }

    await this.authService.logout(refreshToken, id);
    res.clearCookie('refreshToken');
    return res.send({ message: 'User loged out successfully' });
  }

  // Send the refresh_token in Authorization
  @Public()
  @UseGuards(RtGuard)
  @Get('/refresh')
  @HttpCode(HttpStatus.OK)
  async refreshTokens(@Req() req: Request, @Res() res: Response) {
    const { refreshToken } = req.cookies;
    const { id } = req.user;

    if (!refreshToken || !id) {
      throw new UnauthorizedException('Not enough data to update the token');
    }

    const tokenData = await this.tokenService.refreshTokens(id, refreshToken);

    // Send cookie
    const cookieExpiresInterval = parseInt(
      process.env.COOKIE_EXPIRES_INTERVAL,
      10,
    );

    res.cookie('refreshToken', tokenData.refreshToken, {
      httpOnly: true,
      expires: new Date(Date.now() + cookieExpiresInterval),
      // secure: true,
      sameSite: 'strict',
    });

    return res.send(tokenData);
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
