import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthService } from './auth.service';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'passport-jwt') {
    constructor(private readonly authService: AuthService) {
        super({
            jwtFromRequest: ExtractJwt.fromHeader('x-access-token'),
            secretOrKey: 'secretKey',
        });
    }

    async validate(payload: JwtPayload, done: Function) {
        const isValid = await this.authService.validateUser(payload);
        if (!isValid) {
            throw new UnauthorizedException();
        }
        done(null, payload);
    }
}
