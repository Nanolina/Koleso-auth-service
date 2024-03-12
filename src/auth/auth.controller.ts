import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request, Response } from 'express';
import { UNKNOWN_ERROR, convertToNumber } from '../common';
import { Public } from '../common/decorators';
import { MyLogger } from '../logger/my-logger.service';
import { TokenService } from '../token/token.service';
import { PasswordResetTokenService } from './../password-reset-token/password-reset-token.service';
import { AuthService } from './auth.service';
import {
  ChangeEmailDto,
  ChangePhoneDto,
  LoginDto,
  SetNewPasswordDto,
  SignupDto,
} from './dto';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private tokenService: TokenService,
    private configService: ConfigService,
    private passwordResetTokenService: PasswordResetTokenService,
    private readonly logger: MyLogger,
  ) {}

  private setRefreshTokenCookie(res: Response, refreshToken: string) {
    const cookieExpiresInterval = convertToNumber(
      this.configService.get<string>('COOKIE_EXPIRES_INTERVAL'),
    );

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      expires: new Date(Date.now() + cookieExpiresInterval),
      // secure: true,
      sameSite: 'strict',
    });
  }

  @Public()
  @Post('/signup')
  @HttpCode(HttpStatus.CREATED)
  async signup(
    @Body() dto: SignupDto,
    @Res() res: Response,
  ): Promise<Response> {
    const { tokens, user } = await this.authService.signup(dto);
    await this.setRefreshTokenCookie(res, tokens.refreshToken);

    return res.send({ user, token: tokens.accessToken });
  }

  @Public()
  @Post('/login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginDto, @Res() res: Response): Promise<Response> {
    const { tokens, user } = await this.authService.login(dto);
    await this.setRefreshTokenCookie(res, tokens.refreshToken);

    return res.send({
      user,
      token: tokens.accessToken,
    });
  }

  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Req() req: Request, @Res() res: Response) {
    await this.authService.logout(req.user.id);
    res.clearCookie('refreshToken');

    return res.sendStatus(200);
  }

  @Public()
  @Get('/refresh')
  @HttpCode(HttpStatus.OK)
  async refreshTokens(@Req() req: Request, @Res() res: Response) {
    // Get refresh token from cookies
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      this.logger.error({
        method: 'refreshTokens',
        error: 'The token has not been transferred',
      });

      throw new UnauthorizedException(UNKNOWN_ERROR);
    }

    // Get new tokens and user data
    const { tokens, user } =
      await this.tokenService.refreshTokens(refreshToken);

    // Set cookies
    await this.setRefreshTokenCookie(res, tokens.refreshToken);

    return res.send({
      user,
      token: tokens.accessToken,
    });
  }

  @Public()
  @Get('/activate/:activationLinkId')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(
    @Param('activationLinkId') activationLinkId: string,
    @Res() res: Response,
  ) {
    await this.authService.verifyEmail(activationLinkId);

    const interfaceURL = this.configService.get<string>('SELLER_INTERFACE_URL');

    res.redirect(interfaceURL);
  }

  @Patch('/change-email')
  @HttpCode(HttpStatus.OK)
  async changeEmail(
    @Req() req: Request,
    @Body() dto: ChangeEmailDto,
  ): Promise<ChangeEmailDto> {
    return await this.authService.changeEmail({
      id: req.user.id,
      email: dto.email,
    });
  }

  @Patch('/change-phone')
  @HttpCode(HttpStatus.OK)
  async changePhone(
    @Req() req: Request,
    @Body() dto: ChangePhoneDto,
  ): Promise<ChangePhoneDto> {
    return await this.authService.changePhone({
      id: req.user.id,
      phone: dto.phone,
    });
  }

  @Public()
  @Post('/password/recovery')
  @HttpCode(HttpStatus.OK)
  async requestPasswordRecovery(@Body() dto: ChangeEmailDto): Promise<void> {
    return await this.authService.requestPasswordRecovery({
      email: dto.email,
    });
  }

  @Public()
  @Get('/password/reset/:userId/:passwordResetToken')
  @HttpCode(HttpStatus.OK)
  async resetPassword(
    @Param('userId') userId: string,
    @Param('passwordResetToken') passwordResetToken: string,
    @Res() res: Response,
  ) {
    await this.passwordResetTokenService.verifyAndDelete(
      passwordResetToken,
      userId,
    );

    const interfaceURL = this.configService.get<string>('SELLER_INTERFACE_URL');
    const setNewPasswordURL = `${interfaceURL}/password/set/${userId}`;

    res.redirect(setNewPasswordURL);
  }

  @Public()
  @Post('/password/set/:userId')
  @HttpCode(HttpStatus.OK)
  async setNewPassword(
    @Body() dto: SetNewPasswordDto,
    @Param('userId') userId: string,
    @Res() res: Response,
  ): Promise<Response> {
    const { tokens, user } = await this.authService.setNewPassword({
      userId,
      ...dto,
    });

    await this.setRefreshTokenCookie(res, tokens.refreshToken);

    return res.send({ user, token: tokens.accessToken });
  }
}
