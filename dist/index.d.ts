export type SameSite = 'Lax' | 'Strict' | 'None';
export type CookieOptions = {
    name?: string;
    domain?: string;
    path?: string;
    secure?: boolean;
    sameSite?: SameSite;
    maxAgeSeconds?: number;
};
export type Session = {
    username: string;
    expiresAt: number;
};
export type StoredUser = {
    username: string;
    passwordHash: string | null;
};
export type NewUser = {
    username: string;
    passwordHash: string | null;
};
export type UserStore = {
    getUser(username: string): Promise<StoredUser | null>;
    createUser(user: NewUser): Promise<void>;
};
export type PostgresTaggedTemplate = <T extends readonly unknown[]>(strings: TemplateStringsArray, ...values: unknown[]) => Promise<T>;
export type SimpleAuthOptions = {
    secret: string;
    users: UserStore;
    cookie?: CookieOptions;
};
export type AuthSuccess = {
    username: string;
    headers: Headers;
    cookie: string;
};
export type AuthFailure = {
    error: string;
};
export declare function createSimpleAuth(options: SimpleAuthOptions): {
    cookieName: string;
    signUp(params: {
        username: string;
        password: string;
    }): Promise<AuthSuccess>;
    signIn(params: {
        username: string;
        password: string;
    }): Promise<AuthSuccess>;
    signInAnonymous(username?: string): Promise<AuthSuccess>;
    readSession(request: Request): Promise<Session | null>;
    requireSession(request: Request): Promise<Session>;
    signOut(): AuthSuccess;
};
export declare function normalizeUsername(value: string): string;
export declare function createPostgresUserStore(sql: PostgresTaggedTemplate): UserStore;
export declare function hashPassword(password: string): Promise<string>;
export declare function verifyPassword(password: string, hash: string): Promise<boolean>;
export declare function createSessionCookie(session: {
    username: string;
}, secret: string, cookieOptions?: CookieOptions): Promise<string>;
export declare function readSessionCookie(cookieHeader: string | null, secret: string, cookieName?: string): Promise<Session | null>;
export declare function parseCookie(cookieHeader: string | null): Record<string, string>;
//# sourceMappingURL=index.d.ts.map