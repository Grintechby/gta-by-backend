import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength } from 'class-validator';

export class LoginDto {
  @ApiProperty({
    description: "User's Email",
    example: 'user@example.com',
  })
  @IsEmail({}, { message: 'login.email.invalid' })
  email: string;

  @ApiProperty({
    description: "User's Password",
    example: 'password123',
  })
  @IsString()
  @MinLength(6, { message: 'login.password.minLength' })
  password: string;
}
