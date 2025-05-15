import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';

import * as bcrypt from 'bcrypt';

import { PrismaClient } from 'generated/prisma';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly _logger = new Logger('AuthService')

    constructor(
        private readonly _jwtService: JwtService
    ) {
        super()
    }

    onModuleInit() {
        this.$connect()
        this._logger.log('MongoDB connected')
    }

    async signJwt( payload: JwtPayload ) {
        return this._jwtService.sign(payload)
    }

    async verifyToken( token: string ) {
        try {

            const { sub, iat, exp, ...user } = this._jwtService.verify(token, {
                secret: envs.jwtSecret,
            })

            return {
                user: user,
                token: await this.signJwt(user)
            }
            
        } catch (err) {
            console.log(err);
            throw new RpcException({
                status: 400,
                message: 'Invalid token'
            })
        }
    }

    async registerUser( registerUserDto: RegisterUserDto ) {

        const { email, name, password } = registerUserDto

        try {

            const user = await this.user.findUnique({
                where: { email }
            })

            if ( user ) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                })
            }

            const newUser = await this.user.create({
                data: {
                    email,
                    password: bcrypt.hashSync( password, 10 ),
                    name,
                }
            })

            const { password: _, ...rest } = newUser

            return {
                user: rest,
                token: await this.signJwt(rest)
            }
            
        } catch (err) {
            throw new RpcException({
                status: 400,
                message: err.message
            })
        }

    }

    async loginUser( loginUserDto: LoginUserDto ) {

        const { email, password } = loginUserDto

        try {

            const user = await this.user.findUnique({
                where: { email }
            })

            if ( !user ) {
                throw new RpcException({
                    status: 400,
                    message: 'User not exists'
                })
            }

            const isPasswordValid = bcrypt.compareSync( password, user.password )
            if ( !isPasswordValid ) {
                throw new RpcException({
                    status: 400,
                    message: 'Wrong credentials'
                })
            }

            const { password: _, ...rest } = user

            return {
                user: rest,
                token: await this.signJwt(rest)
            }
            
        } catch (err) {
            throw new RpcException({
                status: 400,
                message: err.message
            })
        }

    }

}
