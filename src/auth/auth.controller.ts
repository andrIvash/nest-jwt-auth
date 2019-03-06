import { Controller, Get, UseGuards, Response, Post, HttpStatus, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('login')
    async loginUser(@Response() res: any, @Body() body: JwtPayload) {
        if (!(body && body.email)) {
            return res.status(HttpStatus.FORBIDDEN).json({ message: 'Email are required!' });
        }
        if (body.email === 'test@test.com') {
            const user = {
                token: await this.authService.createToken(body.email),
            };
            return res.status(HttpStatus.OK).json(user);
        }

        return res.status(HttpStatus.FORBIDDEN).json({ message: 'Email is wrong!' });
    }
}
