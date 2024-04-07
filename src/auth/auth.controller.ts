import {
  BadRequestException,
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
import { RoleType } from '@prisma/client';
import { Request, Response } from 'express';
import { UNKNOWN_ERROR, convertToNumber } from '../common';
import { Public } from '../common/decorators';
import { MyLogger } from '../logger/my-logger.service';
import { TokenService } from '../token/token.service';
import { PasswordResetTokenService } from './../password-reset-token/password-reset-token.service';
import { AuthService } from './auth.service';
import {
  ChangeEmailDto,
  ChangePasswordDto,
  ChangePhoneDto,
  LoginDto,
  SetNewPasswordDto,
  SignupDto,
} from './dto';
import { ChangeEmailResponse } from './types';

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
  @Get('/activate/:activationLinkId/:role')
  @HttpCode(HttpStatus.TEMPORARY_REDIRECT)
  async verifyEmail(
    @Param('activationLinkId') activationLinkId: string,
    @Param('role') role: string,
    @Res() res: Response,
  ) {
    await this.authService.verifyEmail(activationLinkId);
    const sellerInterface = this.configService.get<string>(
      'SELLER_INTERFACE_URL',
    );
    const customerInterface = this.configService.get<string>(
      'CUSTOMER_INTERFACE_URL',
    );

    if (role === RoleType.Seller) {
      return res.redirect(sellerInterface);
    } else if (role === RoleType.Customer) {
      return res.redirect(customerInterface);
    }

    throw new BadRequestException('Invalid user role');
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
  @Get('/password/reset/:userId/:passwordResetToken/:role')
  @HttpCode(HttpStatus.TEMPORARY_REDIRECT)
  async resetPassword(
    @Param('userId') userId: string,
    @Param('passwordResetToken') passwordResetToken: string,
    @Param('role') role: string,
    @Res() res: Response,
  ) {
    await this.passwordResetTokenService.verifyAndDelete(
      passwordResetToken,
      userId,
    );

    const setNewPasswordURL = (interfaceURL: string) =>
      `${interfaceURL}/password/set/${userId}`;

    const sellerInterface = this.configService.get<string>(
      'SELLER_INTERFACE_URL',
    );
    const customerInterface = this.configService.get<string>(
      'CUSTOMER_INTERFACE_URL',
    );

    if (role === RoleType.Seller) {
      return res.redirect(setNewPasswordURL(sellerInterface));
    } else if (role === RoleType.Customer) {
      return res.redirect(setNewPasswordURL(customerInterface));
    }

    throw new BadRequestException('Invalid user role');
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
