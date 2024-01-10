import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JWTService {
  constructor(private jwtService: JwtService) {}

  async createToken(user: any): Promise<string> {
    const payload = { sub: user.id };
    return this.jwtService.sign(payload);
  }
}
