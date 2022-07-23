import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { domainToASCII } from 'url';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    // gen pass
    const hash = await argon.hash(dto.password);

    // save the user
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;
      return user;
    } catch (error) {
      if (
        error instanceof PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ForbiddenException('Credentials taken');
      }
      throw error;
    }
    // return the saved user
  }

  async signin(dto: AuthDto) {
    // find the user
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // if the !user throw exception
    if (!user) throw new ForbiddenException('Credentials Incorrect');

    // compare pass
    const pMatch = await argon.verify(user.hash, dto.password);

    // if pass incorrect throw exception
    if (!pMatch) throw new ForbiddenException('Credentials Incorrect');

    // send back user
    delete user.hash;
    return user;
  }
}
