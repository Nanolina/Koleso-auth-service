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
import { CodeType } from '@prisma/client';
import { Request, Response } from 'express';
import { CodeService } from '../code/code.service';
import { UNKNOWN_ERROR, convertToNumber } from '../common';
import { Public } from '../common/decorators';
import { MyLogger } from '../logger/my-logger.service';
import { TokenService } from '../token/token.service';
import { AuthService } from './auth.service';
import {
  ChangeEmailDto,
  ChangePasswordDto,
  ChangePhoneDto,
  LoginDto,
  ResendCodeDto,
  SetNewPasswordDto,
  SignupDto,
  VerifyCodeDto,
} from './dto';
import { ChangeEmailResponse, EmailResponse } from './types';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private tokenService: TokenService,
    private configService: ConfigService,
    private codeService: CodeService,
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

  @Patch('/users/email')
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

  @Patch('/users/phone')
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

  @Patch('/users/password')
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
  @Post('/passwords/recovery')
  @HttpCode(HttpStatus.OK)
  async requestPasswordRecovery(
    @Body() dto: ChangeEmailDto,
  ): Promise<EmailResponse> {
    return await this.authService.requestPasswordRecovery({
      email: dto.email,
    });
  }

  @Post('/passwords/set')
  @HttpCode(HttpStatus.OK)
  async setNewPassword(
    @Body() dto: SetNewPasswordDto,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<Response> {
    const { tokens, user } = await this.authService.setNewPassword({
      userId: req.user.id,
      ...dto,
    });

    await this.setRefreshTokenCookie(res, tokens.refreshToken);

    return res.send({ user, token: tokens.accessToken });
  }

  @Public()
  @Post('/codes/:codeType/verify')
  @HttpCode(HttpStatus.OK)
  async verifyCode(
    @Param('codeType') codeType: CodeType,
    @Body() dto: VerifyCodeDto,
    @Res() res: Response,
  ): Promise<Response> {
    const userFromDB = await this.authService.getUserByEmail(dto.email);
    const userId = userFromDB.id;
    await this.codeService.verify(dto.code, codeType, userId);

    const { tokens, user } = await this.authService.getAuthResponse(userFromDB);

    switch (codeType) {
      case CodeType.PASSWORD_RESET:
        await this.setRefreshTokenCookie(res, tokens.refreshToken);
        return res.send({ user, token: tokens.accessToken });
      case CodeType.EMAIL_CONFIRMATION:
        const isVerifiedEmail =
          await this.authService.switchOnVerifiedEmail(userId);
        await this.setRefreshTokenCookie(res, tokens.refreshToken);

        return res.send({
          user: {
            ...user,
            isVerifiedEmail,
          },
          token: tokens.accessToken,
        });
      case CodeType.PHONE_CONFIRMATION:
      default:
        return;
    }
  }

  @Public()
  @Post('/codes/:codeType/resend')
  @HttpCode(HttpStatus.OK)
  async resendCode(
    @Param('codeType') codeType: CodeType,
    @Body() dto: ResendCodeDto,
  ): Promise<EmailResponse> {
    return await this.codeService.resend(dto.email, codeType);
  }
}
