import { IsEmail, IsString, IsStrongPassword } from "class-validator";

export class SignInUserDTO {
    @IsEmail()
    email: string;

    @IsString()
    password: string;
}
