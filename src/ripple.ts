import type { createSimpleAuth } from './index.js';

type SimpleAuth = ReturnType<typeof createSimpleAuth>;

export type RippleContext = {
  request: Request;
  params: Record<string, string>;
};

export type RippleAuthAdapterOptions = {
  getAuth(): SimpleAuth;
};

type AuthBody = {
  username?: unknown;
  password?: unknown;
};

export function createRippleAuthHandlers(options: RippleAuthAdapterOptions) {
  return {
    handleAuth(context: RippleContext) {
      return handleRippleAuth(context, options.getAuth());
    },

    handleBootstrap(context: RippleContext) {
      return handleRippleBootstrap(context, options.getAuth());
    },
  };
}

export async function handleRippleBootstrap(context: RippleContext, auth: SimpleAuth) {
  const session = await auth.readSession(context.request);
  return json({
    session: session ? { username: session.username } : null,
  });
}

export async function handleRippleAuth(context: RippleContext, auth: SimpleAuth) {
  try {
    if (context.params.action === 'signout') {
      const result = auth.signOut();
      return json({ session: null }, { headers: result.headers });
    }

    const body = await readJson<AuthBody>(context.request);

    if (context.params.action === 'anonymous') {
      const username = typeof body.username === 'string' && body.username.trim() ? body.username : undefined;
      const result = await auth.signInAnonymous(username);
      return json({ session: { username: result.username } }, { headers: result.headers });
    }

    const username = typeof body.username === 'string' ? body.username : '';
    const password = typeof body.password === 'string' ? body.password : '';

    if (context.params.action === 'signup') {
      const result = await auth.signUp({ username, password });
      return json({ session: { username: result.username } }, { headers: result.headers });
    }

    if (context.params.action === 'signin') {
      const result = await auth.signIn({ username, password });
      return json({ session: { username: result.username } }, { headers: result.headers });
    }
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : 'Authentication failed.' }, { status: 400 });
  }

  return json({ error: 'Unknown auth action.' }, { status: 404 });
}

async function readJson<T>(request: Request): Promise<T> {
  try {
    return (await request.json()) as T;
  } catch {
    return {} as T;
  }
}

function json(value: unknown, init: ResponseInit = {}) {
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'application/json');
  return new Response(JSON.stringify(value), { ...init, headers });
}
