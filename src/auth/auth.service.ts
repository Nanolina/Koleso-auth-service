import { Injectable } from '@nestjs/common';
import * as dotenv from 'dotenv';
import { PrismaService } from '../prisma/prisma.service';
import { TokenService } from '../token/token.service';
import { SignUpDto } from './dto';
import { Tokens } from './types';

dotenv.config();

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private tokenService: TokenService,
  ) {}

  async signUp(dto: SignUpDto): Promise<Tokens> {
    const { password, repeatedPassword, email, phone } = dto;

    // Password comparison
    if (password !== repeatedPassword) {
      throw new Error('Passwords do not match');
    }

    // Hash the password
    const hashedPassword = await this.tokenService.hashData(password);

    const newUser = await this.prisma.user.create({
      data: {
        email,
        phone,
        password: hashedPassword,
      },
    });

    const tokens = await this.tokenService.getTokens(newUser.id);

    await this.tokenService.createRefreshToken(
      newUser.id,
      tokens.refresh_token,
    );
    return tokens;
  }

  async login() {}
  async logout() {}
}
