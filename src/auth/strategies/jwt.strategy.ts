import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UsersService } from 'users/users.service';

export interface JwtPayload {
  sub: number;
  email: string;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly usersService: UsersService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'abrakadabra_secret_key',
    });
  }

  async validate(payload: JwtPayload) {
    const { id, email, name, role } = await this.usersService.findById(
      payload.sub,
    );

    if (!id) {
      throw new UnauthorizedException('auth.token.invalid');
    }

    return { id, email, name, role };
  }
}
