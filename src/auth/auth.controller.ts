import { Body, Controller, Post, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInUserDTO } from './dto/sign-in-user.dto';
import { CreateUserDTO } from './dto/create-user.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}
    // NOTE(future): Implement the methods using the DTOs for validation
    // @Post('admin-login')
    // adminLogin() {
    //
    // }

    // // NOTE(future): Implement the methods using the DTOs for validation
    // @Post('admin-register')
    // adminRegister() {
    //
    // }

    @Post('login')
    async login(@Body() signInUserDto: SignInUserDTO) {
        try {
            return await this.authService.signInWithEmailAndPassword(
                signInUserDto.email,
                signInUserDto.password,
            );
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            // Map common auth errors to 401 Unauthorized
            if (/invalid|credential|sign-in/i.test(message)) {
                throw new UnauthorizedException(message);
            }
            throw new BadRequestException(message);
        }
    }

    @Post('register')
    async register(@Body() createUserDto: CreateUserDTO) {
        try {
            return await this.authService.signUpWithEmailAndPassword(
                createUserDto.email,
                createUserDto.password,
                createUserDto.fullName,
            );
        } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            throw new BadRequestException(message);
        }
    }
}
