import { Logger } from 'winston';
import { HttpException, Inject, Injectable } from '@nestjs/common';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { ValidationService } from 'src/common/validation.service';
import { PrismaService } from 'src/common/prisma.service';
import { LoginUserRequest, RegisterUserRequest, UserResponse } from 'src/model/user.model';
import { UserValidation } from './user.validation';
import * as bcrypt from 'bcrypt';
import {v4 as uuid} from 'uuid';

@Injectable()
export class UserService {
  constructor(
    private validationService: ValidationService,
    @Inject(WINSTON_MODULE_PROVIDER) private logger: Logger,
    private prismaService: PrismaService,
  ) {}

  async register(request: RegisterUserRequest): Promise<UserResponse> {
    this.logger.info(`Register new user ${JSON.stringify(request)}`);
    const registerReq = this.validationService.validate(
      UserValidation.REGISTER,
      request,
    );

    const totalUserWithSameName = await this.prismaService.user.count({
      where: {
        username: registerReq.username,
      },
    });

    if (totalUserWithSameName != 0) {
      throw new HttpException('Username already exists', 400);
    }

    registerReq.password = await bcrypt.hash(registerReq.password, 10);

    const user = await this.prismaService.user.create({
      data: registerReq,
    });

    return {
      username: user.username,
      name: user.name,
    };
  }

  async login(request: LoginUserRequest): Promise<UserResponse> {
    this.logger.info(`UserService.login(${JSON.stringify(request)})`)
    const loginRequest: LoginUserRequest = this.validationService.validate(
      UserValidation.LOGIN,
      request
    );

    let user = await this.prismaService.user.findUnique({
      where: {
        username: loginRequest.username
      }
    });

    if (!user) {
      throw new HttpException('Username Or password is invalid', 401);
    }

    const isPasswordValid = await bcrypt.compare(
      loginRequest.password,
      user.password
    );

    if(!isPasswordValid){
      throw new HttpException('Username or password is invalid', 401);
    }

    user = await this.prismaService.user.update({
      where: {
        username: loginRequest.username
      },
      data: {
        token: uuid()
      }
    });

    return {
      username: user.username,
      name: user.name,
      token: user.token
    }
  }
}
