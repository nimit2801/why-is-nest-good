import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { JwtGaurd } from 'src/auth/gaurd';
import { GetUser } from 'src/auth/decorator';
import { User } from '@prisma/client';

@UseGuards(JwtGaurd)
@Controller('users')
export class UserController {
  @Get('me')
  getMe(@GetUser() user: User) {
    // get info of the current user based on the access token
    return user;
  }
}

