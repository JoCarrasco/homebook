import { IsEmail, IsString, MinLength } from "class-validator";

export class SignInUserDTO {
    @IsEmail()
    email: string;

    @MinLength(6)
    @IsString()
    password: string;
}
