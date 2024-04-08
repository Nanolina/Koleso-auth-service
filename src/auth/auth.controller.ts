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
import { VerificationCodeService } from '../verification-code/verification-code.service';
import { AuthService } from './auth.service';
import {
  ChangeEmailDto,
  ChangePasswordDto,
  ChangePhoneDto,
  LoginDto,
  SetNewPasswordDto,
  SignupDto,
  VerifyCodeDto,
} from './dto';
import { ChangeEmailResponse, VerifyConfirmationCodeResponse } from './types';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private tokenService: TokenService,
    private configService: ConfigService,
    private verificationCodeService: VerificationCodeService,
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
        method: 'auth-refreshTokens',
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

  @Post('/verify-confirmation-code')
  @HttpCode(HttpStatus.OK)
  async verifyConfirmationCode(
    @Req() req: Request,
    @Body() dto: VerifyCodeDto,
  ): Promise<VerifyConfirmationCodeResponse> {
    const userId = req.user.id;
    const codeType = dto.codeType;
    await this.verificationCodeService.verify(dto.code, userId, codeType);

    switch (codeType) {
      case 'EMAIL_CONFIRMATION':
        return await this.authService.toggleIsVerifiedEmail(userId);
      case 'PHONE_CONFIRMATION':
      // return await this.authService.toggleIsVerifiedPhone(userId);
      default:
        return { isVerifiedEmail: false };
    }
  }

  @Public()
  @Post('/verify-password-reset-code')
  @HttpCode(HttpStatus.OK)
  async verifyPasswordResetCode(@Body() dto: VerifyCodeDto): Promise<void> {
    return await this.verificationCodeService.verify(
      dto.code,
      undefined,
      'PASSWORD_RESET',
    );
  }

  @Patch('/change-email')
  @HttpCode(HttpStatus.OK)
  async changeEmail(
    @Req() req: Request,
    @Body() dto: ChangeEmailDto,
  ): Promise<ChangeEmailResponse> {
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

  @Patch('/change-password')
  @HttpCode(HttpStatus.OK)
  async changePassword(
    @Req() req: Request,
    @Body() dto: ChangePasswordDto,
  ): Promise<boolean> {
    return await this.authService.changePassword({
      id: req.user.id,
      ...dto,
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
