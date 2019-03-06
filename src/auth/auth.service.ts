import { Injectable, Req } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService {
    constructor(private readonly jwtService: JwtService) {}

    async createToken(email: string) {
        const user: JwtPayload = { email };
        const accessToken = this.jwtService.sign(user);
        return {
            expiresIn: 3600,
            accessToken,
        };
    }

    async validateUser(payload: JwtPayload): Promise<any> {
        if (payload && payload.email === 'test@test.com') { // db request here
            return Promise.resolve(payload);
        }
        return Promise.reject(false);
    }
}
