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
}