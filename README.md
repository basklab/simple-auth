# simple-auth

Tiny signed-cookie auth helpers for server-rendered apps. No JWTs. The session cookie stores a username plus expiry and is authenticated with HMAC-SHA-256.

## Install from GitHub

```sh
pnpm add github:basklab/simple-auth
```

## Cookie model

The cookie value is:

```txt
base64url({"username":"alice","expiresAt":...}).base64url(hmac)
```

It is readable by the server, tamper-evident, `HttpOnly`, and can be cleared without a session table.

## Example

```ts
import { createSimpleAuth } from '@basklab/simple-auth';

const auth = createSimpleAuth({
  secret: process.env.AUTH_SECRET!,
  users: {
    async getUser(username) {
      // return { username, passwordHash } or null
    },
    async createUser(user) {
      // insert user.username and user.passwordHash
    },
  },
});

const result = await auth.signIn({ username: 'alice', password: 'password' });
const session = await auth.readSession(request);
```

Anonymous users are passwordless rows with `password_hash = null`:

```ts
const anonymous = await auth.signInAnonymous();
// or reserve a specific visible guest name
const namedGuest = await auth.signInAnonymous('guest-alice');
```

With `postgres`:

```ts
import postgres from 'postgres';
import { createPostgresUserStore, createSimpleAuth } from '@basklab/simple-auth';

const sql = postgres(process.env.POSTGRES_URL!);
const auth = createSimpleAuth({
  secret: process.env.AUTH_SECRET!,
  users: createPostgresUserStore(sql),
});
```

## Ripple adapter

The Ripple adapter is exported from a separate subpath and uses only structural Web/Ripple-compatible types. It does not import Ripple.

```ts
import { createRippleAuthHandlers } from '@basklab/simple-auth/ripple';

export const { handleAuth, handleBootstrap } = createRippleAuthHandlers({
  getAuth: () => auth,
});
```

Apply `schema.sql` if you want the default table shape:

```sh
psql "$POSTGRES_URL" -f schema.sql
```
