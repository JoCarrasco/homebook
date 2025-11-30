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
        this.authProvider = new SupabaseAuthCoreProvider(supabaseUrl, supabaseAnonKey);
    }

    signInWithEmailAndPassword(email: string, password: string): Promise<AuthSignInMethodResult> {
        // Implementation for signing in with email and password
        return this.authProvider.emailPasswordSignIn(email, password);
    }

    signUpWithEmailAndPassword(email: string, password: string, fullName: string): Promise<AuthSignInMethodResult> {
        // Implementation for signing up with email and password
        return this.authProvider.emailPasswordSignUp(email, password, fullName);
    }
}
