export interface AuthSignInMethodResult {
    userId: string;
    token: string;
    expiresIn: number; // in seconds
    // When true, indicates the user was created but a session/token was not
    // returned (commonly because the project requires email confirmation).
    // Optional so existing callers remain compatible.
    needsConfirmation?: boolean;
}

export abstract class AuthSignInMethods {
    abstract emailPasswordSignIn(email: string, password: string): Promise<AuthSignInMethodResult>;
    abstract googleSignIn(): Promise<AuthSignInMethodResult>;
    abstract appleSignIn(): Promise<AuthSignInMethodResult>;
}

export abstract class AuthCoreIdentityProvider extends AuthSignInMethods {
    abstract getUserIdFromToken(token: string): Promise<string>;
    abstract validateToken(token: string): Promise<boolean>;
    abstract revokeToken(token: string): Promise<void>;
    abstract refreshToken(token: string): Promise<AuthSignInMethodResult>;

    // Sign Up Methods
    abstract emailPasswordSignUp(email: string, password: string, fullName: string): Promise<AuthSignInMethodResult>;

    // NOTE(future): The following methods are commented out for future implementation
    // abstract googleSignUp(): Promise<AuthSignInMethodResult>;
    // abstract appleSignUp(): Promise<AuthSignInMethodResult>;
}

export class AuthCoreIdentityProviderBase extends AuthCoreIdentityProvider {
    async emailPasswordSignIn(email: string, password: string): Promise<AuthSignInMethodResult> {
        throw new Error("Method not implemented.");
    }
    async googleSignIn(): Promise<AuthSignInMethodResult> {
        throw new Error("Method not implemented.");
    }
    async appleSignIn(): Promise<AuthSignInMethodResult> {
        throw new Error("Method not implemented.");
    }
    async getUserIdFromToken(token: string): Promise<string> {
        throw new Error("Method not implemented.");
    }
    async validateToken(token: string): Promise<boolean> {
        throw new Error("Method not implemented.");
    }
    async revokeToken(token: string): Promise<void> {
        throw new Error("Method not implemented.");
    }
    async refreshToken(token: string): Promise<AuthSignInMethodResult> {
        throw new Error("Method not implemented.");
    }
    async emailPasswordSignUp(email: string, password: string, fullName: string): Promise<AuthSignInMethodResult> {
        throw new Error("Method not implemented.");
    }
}