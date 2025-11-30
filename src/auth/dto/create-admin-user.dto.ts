import { IsEmail, IsString, IsStrongPassword } from "class-validator";

export class CreateAdminUserDTO {
    @IsEmail()
    email: string;

    @IsStrongPassword()
    password: string;

    @IsString()
    fullName: string;
}