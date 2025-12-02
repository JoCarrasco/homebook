import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthSignInMethodResult } from './classes/auth-core-provider.class';
import { SupabaseAuthCoreProvider } from './featured/supabase-authentication-provider';

@Injectable()
export class AuthService {
    private authProvider: SupabaseAuthCoreProvider;

    constructor(private readonly configService: ConfigService) {
        const supabaseUrl = this.configService.get<string>('SUPABASE_URL') || '';
        const supabaseAnonKey = this.configService.get<string>('SUPABASE_ANON_KEY') || '';
        const emailOtpExpirationSeconds = this.configService.get<number>('SUPABASE_EMAIL_OTP_EXPIRATION_SECONDS') || 3600;
        const emailOtpLength = this.configService.get<number>('SUPABASE_EMAIL_OTP_LENGTH') || 6;
        this.authProvider = new SupabaseAuthCoreProvider(supabaseUrl, supabaseAnonKey, emailOtpExpirationSeconds, emailOtpLength);
    }

    signInWithEmailAndPassword(email: string, password: string): Promise<AuthSignInMethodResult> {
        return this.authProvider.emailPasswordSignIn(email, password);
    }

    signUpWithEmailAndPassword(email: string, password: string, fullName: string): Promise<AuthSignInMethodResult> {
        return this.authProvider.emailPasswordSignUp(email, password, fullName);
    }

    redirectSuccessfulRegistration(accessToken: string): string {
        return `${this.configService.get<string>('CLIENT_APP_URL')}/registration-success?token=${accessToken}`;
    }

    async storeTokens(tokens: { access_token: string; refresh_token: string; expires_in: string; token_type: string }) {
        // Forward to the auth provider which will validate the token and
        // produce cookie metadata that the controller can use to set the
        // HttpOnly cookie on the response.
        return await this.authProvider.storeTokensInHttpOnlyCookie(tokens);
    }
}
