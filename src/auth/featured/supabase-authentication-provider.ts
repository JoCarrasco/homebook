import { AuthCoreIdentityProviderBase, AuthSignInMethodResult } from "../classes/auth-core-provider.class";
import { createClient } from '@supabase/supabase-js'

// Using the npm package "@supabase/supabase-js"
// More information at: https://github.com/supabase/supabase-js
// A small, test-friendly subset of the supabase client surface we use.
export interface ISupabaseClient {
    auth: {
        signInWithPassword: (credentials: { email: string; password: string }) => Promise<{
            data: { user: { id: string } | null; session: { access_token: string; expires_in: number } | null };
            error: any | null;
        }>;
        signUp: (credentials: { email: string; password: string; options?: { data: { fullName?: string } } }) => Promise<{
            data: { user: { id: string } | null; session: { access_token: string; expires_in: number } | null };
            error: any | null;
        }>;
        getUser: (token: string) => Promise<{
            data: { user: { id: string } | null };
            error: any | null;
        }>;
        signOut: () => Promise<{ error: any | null }>;
    };
}

/**
 * Supabase-backed implementation of the core auth provider.
 *
 * Notes for testability:
 * - Accepts an optional `client` allowing unit tests to inject a mock client.
 * - Uses async/await and throws JS Errors with clear messages for failure cases.
 * - Validates constructor inputs when no client is provided to avoid creating a broken client.
 */
export class SupabaseAuthCoreProvider extends AuthCoreIdentityProviderBase {
    private readonly client: ISupabaseClient;

    constructor(
        private readonly supabaseUrl: string,
        private readonly supabaseAnonKey: string,
        private readonly emailOtpExpirationSeconds: number,
        private readonly emailOtpLength: number,
        client?: ISupabaseClient, // optional injection for tests
    ) {
        super();

        if (client) {
            this.client = client;
        } else {
            if (!supabaseUrl || !supabaseAnonKey) {
                throw new Error('Supabase URL and ANON KEY must be provided when not injecting a client');
            }
            // createClient may throw for invalid args in some versions; keep it behind validation
            this.client = createClient(supabaseUrl, supabaseAnonKey) as unknown as ISupabaseClient;
        }
    }

    async emailPasswordSignUp(email: string, password: string, fullName: string): Promise<AuthSignInMethodResult> {
        try {
            const { data, error } = await this.client.auth.signUp({ email, password, options: { data: { fullName } } });
            if (error) {
                // Normalize error to Error type for callers and tests
                const message = (error && (error.message || error.toString())) || 'Unknown sign-up error';
                throw new Error(`Sign-up failed: ${message}`);
            }
            if (!data || !data.user) {
                throw new Error('Sign-up failed: no user returned');
            }
            // If signup returns a session, return it. If not, try to sign the user in
            // immediately (Supabase may require email confirmation; this will fail in that case).
            if (data.session && data.session.access_token) {
                return {
                    userId: data.user.id,
                    token: data.session.access_token,
                    expiresIn: data.session.expires_in || 0,
                    needsConfirmation: false,
                    message: `User registered successfully, please check your email for confirmation link, it must have been sent to ${email}`,
                };
            }

            // Attempt to sign in to obtain a session when signup didn't return one.
            try {
                const signInResult = await this.client.auth.signInWithPassword({ email, password });
                if (!signInResult.error && signInResult.data?.session && signInResult.data.session.access_token) {
                    return {
                        userId: data.user.id,
                        token: signInResult.data.session.access_token,
                        expiresIn: signInResult.data.session.expires_in || 0,
                        needsConfirmation: false,
                    };
                }
                // If sign-in failed (e.g. confirmation required), fall through and return userId only.
            } catch (_signInErr) {
                // ignore sign-in errors here; caller can attempt sign-in separately
            }

            // No session available — return userId and empty token/expiresIn to keep the contract.
            return {
                userId: data.user.id,
                token: '',
                expiresIn: 0,
                needsConfirmation: true,
            };
        } catch (err) {
            // Ensure we always throw an Error instance with a helpful message
            if (err instanceof Error) throw err;
            throw new Error(String(err));
        }
    }

    async emailPasswordSignIn(email: string, password: string): Promise<AuthSignInMethodResult> {
        try {
            const { data, error } = await this.client.auth.signInWithPassword({ email, password });
            if (error) {
                const message = (error && (error.message || error.toString())) || 'Unknown sign-in error';
                throw new Error(`Sign-in failed: ${message}`);
            }
            if (!data || !data.user) {
                throw new Error('Sign-in failed: no user returned');
            }
            return {
                userId: data.user.id,
                token: data.session?.access_token || '',
                expiresIn: data.session?.expires_in || 0,
            };
        } catch (err) {
            if (err instanceof Error) throw err;
            throw new Error(String(err));
        }
    }

    async activateUserWithEmailToken(_token: string): Promise<void> {
        // Supabase automatically handles email token activation via link;
        // no action needed here.
        return;
    }

    /**
     * Returns true when token appears valid. Does not throw for client errors; returns false instead.
     */
    async validateToken(token: string): Promise<boolean> {
        try {
            const { data, error } = await this.client.auth.getUser(token);
            if (error) {
                // treat client errors as invalid token rather than throwing
                return false;
            }
            return !!data?.user;
        } catch (_err) {
            return false;
        }
    }

    async getUserIdFromToken(token: string): Promise<string> {
        try {
            const { data, error } = await this.client.auth.getUser(token);
            if (error) {
                const message = (error && (error.message || error.toString())) || 'Unknown error when getting user';
                throw new Error(`Invalid token: ${message}`);
            }
            if (!data?.user) {
                throw new Error('Invalid token: no user found');
            }
            return data.user.id;
        } catch (err) {
            if (err instanceof Error) throw err;
            throw new Error(String(err));
        }
    }

    /**
     * Revokes the current session. The abstract signature requires a token parameter;
     * some supabase clients do not accept a token for signOut; we keep the parameter for signature
     * compatibility and ignore it for the client that doesn't need it.
     */
    async revokeToken(_token: string): Promise<void> {
        try {
            const { error } = await this.client.auth.signOut();
            if (error) {
                const message = (error && (error.message || error.toString())) || 'Unknown error when signing out';
                throw new Error(`Failed to revoke token: ${message}`);
            }
        } catch (err) {
            if (err instanceof Error) throw err;
            throw new Error(String(err));
        }
    }

    async storeTokensInHttpOnlyCookie(tokens: { access_token: string; refresh_token: string; expires_in: string; token_type: string }): Promise<{ name: string; value: string; options: Record<string, any>; }> {
        // Check the token in Supabase to ensure it's valid before storing
        const isValid = await this.validateToken(tokens.access_token);
        if (!isValid) {
            throw new Error('Cannot store tokens: access token is invalid');
        }
        // Build a cookie-safe representation of the tokens. We encode the minimal
        // required fields as a base64 JSON string so the client cannot access it
        // via JavaScript (cookie is httpOnly) and the backend can decode it later.
        const payload = {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            token_type: tokens.token_type,
        };

        const cookieValue = Buffer.from(JSON.stringify(payload)).toString('base64');

        // Calculate maxAge in milliseconds from expires_in which Supabase provides in seconds
        const expiresSeconds = parseInt(tokens.expires_in as unknown as string, 10) || 0;
        const maxAgeMs = expiresSeconds > 0 ? expiresSeconds * 1000 : undefined;

        // Return an object describing the cookie to set. The controller or service
        // that calls this method is responsible for actually setting the Set-Cookie
        // header on the HTTP response using the returned metadata.
        return {
            name: 'homs_auth_session',
            value: cookieValue,
            options: {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                path: '/',
                maxAge: maxAgeMs,
            },
        };
    }
}