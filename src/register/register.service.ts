import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './register.dto';

@Injectable()
export class RegisterService {
  constructor(private prisma: PrismaService) {}

  async register(registerDto: RegisterDto): Promise<void> {
    const { password, repeatedPassword, email, phone } = registerDto;

    if (password !== repeatedPassword) {
      throw new Error('Passwords do not match');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await this.prisma.user.create({
      data: {
        email,
        phone,
        password: hashedPassword,
      },
    });
  }
}
