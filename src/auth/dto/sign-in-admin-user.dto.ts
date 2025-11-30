import { IsEmail, IsStrongPassword } from "class-validator";

export class SignInAdminUserDTO {
    @IsEmail()
    email: string;

    @IsStrongPassword()
    password: string;
}
