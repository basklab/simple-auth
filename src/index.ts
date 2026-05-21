import { createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);

const DEFAULT_COOKIE_NAME = 'simple_auth';
const DEFAULT_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;
const PASSWORD_SCHEME = 'scrypt';
const PASSWORD_KEY_LENGTH = 32;
const PASSWORD_SALT_LENGTH = 16;

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

export type PostgresTaggedTemplate = <T extends readonly unknown[]>(
  strings: TemplateStringsArray,
  ...values: unknown[]
) => Promise<T>;

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

type SessionPayload = {
  username: string;
  expiresAt: number;
};

export function createSimpleAuth(options: SimpleAuthOptions) {
  assertSecret(options.secret);
  const cookie = normalizeCookieOptions(options.cookie);

  return {
    cookieName: cookie.name,

    async signUp(params: { username: string; password: string }): Promise<AuthSuccess> {
      const username = normalizeUsername(params.username);
      assertUsername(username);
      assertPassword(params.password);

      const existing = await options.users.getUser(username);
      if (existing) {
        throw new Error('An account with that username already exists.');
      }

      await options.users.createUser({
        username,
        passwordHash: await hashPassword(params.password),
      });

      return issueAuthSuccess(username, options.secret, cookie);
    },

    async signIn(params: { username: string; password: string }): Promise<AuthSuccess> {
      const username = normalizeUsername(params.username);
      const user = await options.users.getUser(username);
      if (!user?.passwordHash || !(await verifyPassword(params.password, user.passwordHash))) {
        throw new Error('Invalid username or password.');
      }

      return issueAuthSuccess(username, options.secret, cookie);
    },

    async signInAnonymous(username?: string): Promise<AuthSuccess> {
      const explicitUsername = username !== undefined;

      for (let attempt = 0; attempt < 5; attempt += 1) {
        const normalized = normalizeUsername(username ?? `guest-${randomBytes(6).toString('hex')}`);
        assertUsername(normalized);

        const existing = await options.users.getUser(normalized);
        if (existing) {
          if (explicitUsername) {
            throw new Error('That username is already taken.');
          }
          continue;
        }

        await options.users.createUser({ username: normalized, passwordHash: null });
        return issueAuthSuccess(normalized, options.secret, cookie);
      }

      throw new Error('Could not create an anonymous user.');
    },

    async readSession(request: Request): Promise<Session | null> {
      return readSessionCookie(request.headers.get('cookie'), options.secret, cookie.name);
    },

    async requireSession(request: Request): Promise<Session> {
      const session = await readSessionCookie(request.headers.get('cookie'), options.secret, cookie.name);
      if (!session) {
        throw new Error('Not authenticated.');
      }
      return session;
    },

    signOut(): AuthSuccess {
      const clearCookie = serializeCookie(cookie.name, '', {
        ...cookie,
        maxAgeSeconds: 0,
      });
      return {
        username: '',
        cookie: clearCookie,
        headers: headersWithCookie(clearCookie),
      };
    },
  };
}

export function normalizeUsername(value: string): string {
  return value.trim().toLowerCase();
}

export function createPostgresUserStore(sql: PostgresTaggedTemplate): UserStore {
  return {
    async getUser(username) {
      const rows = await sql<Array<{ username: string; password_hash: string | null }>>`
        select username, password_hash
        from simple_auth_users
        where username = ${username}
      `;
      const user = rows[0];
      return user ? { username: user.username, passwordHash: user.password_hash } : null;
    },

    async createUser(user) {
      await sql`
        insert into simple_auth_users (username, password_hash)
        values (${user.username}, ${user.passwordHash})
      `;
    },
  };
}

export async function hashPassword(password: string): Promise<string> {
  assertPassword(password);
  const salt = randomBytes(PASSWORD_SALT_LENGTH).toString('base64url');
  const key = (await scrypt(password, salt, PASSWORD_KEY_LENGTH)) as Buffer;
  return `${PASSWORD_SCHEME}$${salt}$${key.toString('base64url')}`;
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  const [scheme, salt, expected] = hash.split('$');
  if (scheme !== PASSWORD_SCHEME || !salt || !expected) {
    return false;
  }

  const actual = (await scrypt(password, salt, PASSWORD_KEY_LENGTH)) as Buffer;
  const expectedBytes = Buffer.from(expected, 'base64url');
  return actual.length === expectedBytes.length && timingSafeEqual(actual, expectedBytes);
}

export async function createSessionCookie(
  session: { username: string },
  secret: string,
  cookieOptions?: CookieOptions,
): Promise<string> {
  assertSecret(secret);
  const cookie = normalizeCookieOptions(cookieOptions);
  const payload: SessionPayload = {
    username: normalizeUsername(session.username),
    expiresAt: Date.now() + cookie.maxAgeSeconds * 1000,
  };
  assertUsername(payload.username);

  const encodedPayload = base64url(JSON.stringify(payload));
  const signature = sign(encodedPayload, secret);
  return serializeCookie(cookie.name, `${encodedPayload}.${signature}`, cookie);
}

export async function readSessionCookie(
  cookieHeader: string | null,
  secret: string,
  cookieName = DEFAULT_COOKIE_NAME,
): Promise<Session | null> {
  assertSecret(secret);
  const value = parseCookie(cookieHeader)[cookieName];
  if (!value) return null;

  const [encodedPayload, signature] = value.split('.');
  if (!encodedPayload || !signature) return null;
  if (!constantTimeEqual(signature, sign(encodedPayload, secret))) return null;

  const payload = parseSessionPayload(encodedPayload);
  if (!payload || payload.expiresAt <= Date.now()) return null;
  return payload;
}

export function parseCookie(cookieHeader: string | null): Record<string, string> {
  if (!cookieHeader) return {};
  const cookies: Record<string, string> = {};
  for (const pair of cookieHeader.split(';')) {
    const index = pair.indexOf('=');
    if (index === -1) continue;
    const key = pair.slice(0, index).trim();
    const value = pair.slice(index + 1).trim();
    if (key) cookies[key] = decodeURIComponent(value);
  }
  return cookies;
}

function issueAuthSuccess(username: string, secret: string, cookie: Required<CookieOptions>): AuthSuccess {
  const payload: SessionPayload = {
    username,
    expiresAt: Date.now() + cookie.maxAgeSeconds * 1000,
  };
  const encodedPayload = base64url(JSON.stringify(payload));
  const signedCookie = serializeCookie(cookie.name, `${encodedPayload}.${sign(encodedPayload, secret)}`, cookie);
  return {
    username,
    cookie: signedCookie,
    headers: headersWithCookie(signedCookie),
  };
}

function headersWithCookie(cookie: string): Headers {
  return new Headers({ 'Set-Cookie': cookie });
}

function parseSessionPayload(encodedPayload: string): Session | null {
  try {
    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8')) as unknown;
    if (!isSessionPayload(payload)) return null;
    return payload;
  } catch {
    return null;
  }
}

function isSessionPayload(value: unknown): value is SessionPayload {
  if (!value || typeof value !== 'object') return false;
  const payload = value as Record<string, unknown>;
  return typeof payload.username === 'string' && typeof payload.expiresAt === 'number';
}

function sign(value: string, secret: string): string {
  return createHmac('sha256', secret).update(value).digest('base64url');
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function base64url(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}

function normalizeCookieOptions(options: CookieOptions = {}): Required<CookieOptions> {
  return {
    name: options.name ?? DEFAULT_COOKIE_NAME,
    domain: options.domain ?? '',
    path: options.path ?? '/',
    secure: options.secure ?? true,
    sameSite: options.sameSite ?? 'Lax',
    maxAgeSeconds: options.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS,
  };
}

function serializeCookie(name: string, value: string, options: Required<CookieOptions>): string {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${options.path}`,
    `Max-Age=${Math.max(0, Math.floor(options.maxAgeSeconds))}`,
    'HttpOnly',
    `SameSite=${options.sameSite}`,
  ];
  if (options.domain) parts.push(`Domain=${options.domain}`);
  if (options.secure) parts.push('Secure');
  return parts.join('; ');
}

function assertSecret(secret: string): void {
  if (secret.length < 32) {
    throw new Error('Auth secret must be at least 32 characters.');
  }
}

function assertUsername(username: string): void {
  if (!/^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$/.test(username)) {
    throw new Error('Username must be 3-64 lowercase letters, numbers, dots, underscores, or dashes.');
  }
}

function assertPassword(password: string): void {
  if (password.length < 8) {
    throw new Error('Password must be at least 8 characters.');
  }
}
