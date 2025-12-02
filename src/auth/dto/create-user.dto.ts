import { IsEmail, IsString, MinLength } from "class-validator";

export class CreateUserDTO {
    @IsEmail()
    email: string;

    @MinLength(6)
    @IsString()
    password: string;

    @IsString()
    fullName: string;
}