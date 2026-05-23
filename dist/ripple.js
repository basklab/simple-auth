export function createRippleAuthHandlers(options) {
    return {
        handleAuth(context) {
            return handleRippleAuth(context, options.getAuth());
        },
        handleBootstrap(context) {
            return handleRippleBootstrap(context, options.getAuth());
        },
    };
}
export async function handleRippleBootstrap(context, auth) {
    const session = await auth.readSession(context.request);
    return json({
        session: session ? { username: session.username } : null,
    });
}
export async function handleRippleAuth(context, auth) {
    try {
        if (context.params.action === 'signout') {
            const result = auth.signOut();
            return json({ session: null }, { headers: result.headers });
        }
        const body = await readJson(context.request);
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
    }
    catch (error) {
        return json({ error: error instanceof Error ? error.message : 'Authentication failed.' }, { status: 400 });
    }
    return json({ error: 'Unknown auth action.' }, { status: 404 });
}
async function readJson(request) {
    try {
        return (await request.json());
    }
    catch {
        return {};
    }
}
function json(value, init = {}) {
    const headers = new Headers(init.headers);
    headers.set('Content-Type', 'application/json');
    return new Response(JSON.stringify(value), { ...init, headers });
}
