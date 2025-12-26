import { IsString, IsEmail, MinLength, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RegisterDto {
  @ApiProperty({
    description: "User's Email",
    example: 'user@example.com',
  })
  @IsEmail({}, { message: 'register.email.invalid' })
  email: string;

  @ApiProperty({
    description: "User's Password (minimum 6 characters)",
    example: 'password123',
  })
  @IsString()
  @MinLength(6, { message: 'register.password.minLength' })
  password: string;

  @ApiProperty({
    description: "User's Name (optional)",
    example: 'John Doe',
    required: false,
  })
  @IsOptional()
  @IsString()
  name?: string;
}
