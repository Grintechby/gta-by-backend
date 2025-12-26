import { Body, Controller, Get, Param, Post } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { Prisma } from '@prisma/client';
import { UsersService } from 'users/users.service';

@Controller('users')
@ApiTags('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  async createUser(@Body() createUserParams: Prisma.UserCreateInput) {
    const createdUser = await this.usersService.createUser(createUserParams);

    return createdUser;
  }

  @Get(':id')
  async getUserById(@Param('id') id: string) {
    return await this.usersService.findById(Number(id));
  }

  @Get('email/:email')
  async getUserByEmail(@Param('email') email: string) {
    return await this.usersService.findByEmail(email);
  }
}
