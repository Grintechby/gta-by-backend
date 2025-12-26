import { LoginDto } from 'auth/dto/login.dto';
import * as bcrypt from 'bcryptjs';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'users/users.service';
import { RegisterDto } from 'auth/dto/register.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto) {
    const hashedPassword = await bcrypt.hash(registerDto.password, 10);

    const { id, email, name, role } = await this.usersService.createUser({
      email: registerDto.email,
      password: hashedPassword,
      name: registerDto.name,
      role: 'USER',
    });

    const payload = { sub: id, email };
    const accessToken = await this.jwtService.signAsync(payload);

    return {
      user: {
        id,
        email,
        name,
        role,
      },
      accessToken,
    };
  }

  async login(loginDto: LoginDto) {
    const { id, email, name, role, password } =
      await this.usersService.findByEmail(loginDto.email);

    const isPasswordValid = await bcrypt.compare(
      loginDto.password,
      password as string,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('login.password.invalid');
    }

    const payload = { sub: id, email };
    const accessToken = await this.jwtService.signAsync(payload);

    return {
      user: {
        id,
        email,
        name,
        role,
      },
      accessToken,
    };
  }
}
