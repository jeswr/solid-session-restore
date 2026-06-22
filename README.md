# @jeswr/solid-session-restore

> Framework-agnostic, security-audited **silent Solid-OIDC session restore** for
> browser apps — the proven pod-mail pilot, extracted so the suite's vite pod-apps
> consume **one** audited implementation instead of N copies of security-critical
> auth code.

When a returning user closes the tab (without logging out) and reopens the app, the
app should **silently re-establish their session** — no popup, no iframe, no flash of
the login screen — by redeeming their persisted, **DPoP-sender-constrained** refresh
token at the token endpoint (a plain `fetch`). This package is the
framework-agnostic **CORE** of that flow; each app keeps only a **thin wiring layer**
(the provider hook + the mount-time `runSilentRestore` effect).

This is the suite-wide cross-app UX invariant #1 (silent session restore on load).

## Why a shared package

The refresh-token + DPoP-key persistence and the restore decision are
**security-critical** (they store and redeem a credential). Seven copies of that
code is seven attack surfaces and seven things to keep correct. One audited core,
with the security invariants pinned by an adversarial test suite, is the only sane
shape. The pilot lives at `pod-mail/web/src/auth/`; this is its generalisation.

## Install (GitHub, buildless)

The built `dist/` is committed, so it installs and imports under
`ignore-scripts=true` with no build step:

```bash
npm install github:jeswr/solid-session-restore#main
```

```ts
import {
  IndexedDbSessionStore,
  RememberedAccount,
  decideSilentRestore,
  shouldDropRememberedPointer,
  restoreSession,
  toAuthenticatedFetch,
  webIdsEqual,
} from "@jeswr/solid-session-restore";
```

A `check:dist` gate fails the build if the committed `dist/` ever drifts from a
fresh `tsc` build, so the buildless install can never go stale.

## Security invariants (the contract — do not weaken)

These are exactly the pilot's, pinned by the test suite:

- **WebID-scoped isolation.** Account A can never restore account B. The credential
  is keyed by **issuer** in IndexedDB; the remembered pointer names **one**
  last-active WebID → its issuer; and the restore decision **re-checks** that the
  restored WebID equals the last-active WebID (`webid-mismatch` → fail-closed
  teardown).
- **DPoP-bound, not bare Bearer.** The refresh grant carries a DPoP proof signed by
  the **same non-extractable key** the token was sender-constrained to (RFC 9449
  §4.3). A stolen refresh token is useless off-origin.
- **Asymmetric-only.** The persisted DPoP key is an ES256 (P-256 ECDSA) key pair;
  no symmetric/bearer fallback.
- **Non-extractable key.** The DPoP private key is stored in IndexedDB as a
  `CryptoKey` with `extractable: false`. IndexedDB structured-clones it; the raw
  bytes never enter JS or hit disk readably. Callers **must** generate the persisted
  key with `extractable: false`.
- **Clear only on a *definitive* `invalid_grant`.** A dead token (expired / revoked
  / rotation-reuse) is cleared so a doomed restore is not retried. A **transient**
  failure (network / discovery 5xx / abort) **preserves** the credential — a blip on
  load must never force a needless re-login.
- **Fail-closed.** Every "nothing to restore / could not rebuild / could not verify"
  path falls back to login. The decision never asserts a session it could not
  actually rebuild.
- **No access token persisted; the refresh token (and any client secret) is never
  logged.** Only the long-lived, key-bound credential is durable.
- **Public by default; a client secret only when one exists.** The grant uses `none`
  client auth unless the session is a **confidential** client (a persisted
  `client_secret` — the ESS/PodSpaces path), in which case the secret is presented and
  re-persisted across rotation under the same fail-closed / clear-on-logout discipline.
  A confidential method with **no** secret **fails closed** (never downgrades to `none`).
- **Per-app store + pointer.** The IndexedDB DB name and the localStorage key are
  **injectable** per app, so two apps on a shared origin never share a session store
  or a pointer.

## Spec-compliant vs bespoke per-server

This package targets the **Solid-OIDC** profile of OpenID Connect / OAuth 2.0. The
restore flow is almost entirely **standard**; a small, clearly-marked set of behaviours
exists only to interoperate with specific servers' non-conformances. This section draws
that line explicitly (the maintainer asked for it on
[#1](https://github.com/jeswr/solid-session-restore/issues/1)).

### Standard — what follows the OIDC / OAuth / Solid-OIDC specs

| Behaviour | Spec |
|---|---|
| Restore via the **`refresh_token` grant** (a token-endpoint `POST`, no popup/iframe) | [RFC 6749 §6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6) (Refreshing an Access Token) |
| **Refresh tokens are client-bound** — redeemed only by the issuing client; we reuse the original `client_id` | [RFC 6749 §6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6) + [§10.4](https://www.rfc-editor.org/rfc/rfc6749.html#section-10.4) |
| **Refresh-token rotation** — adopt + re-persist a server-issued new refresh token | [OAuth 2.0 Security BCP / RFC 9700 §4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2) |
| Public-client default — **`none`** token-endpoint auth (PKCE / DPoP, no secret) | [RFC 6749 §2.3](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3) · [OIDC Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) |
| Confidential-client **`client_secret_basic`** — secret in an HTTP `Basic` header | [RFC 6749 §2.3.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1) · [OIDC Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) |
| Confidential-client **`client_secret_post`** — secret in the form body | [RFC 6749 §2.3.1](https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1) · [OIDC Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) |
| **DPoP** sender-constrained proof on the grant, signed by the bound key; one **`use_dpop_nonce`** retry | [RFC 9449 §4.3 + §8](https://www.rfc-editor.org/rfc/rfc9449.html) |
| **PKCE** at login (S256), DPoP key generated `extractable: false` | [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) (login is the app's; this package consumes its output) |
| **OIDC Discovery** of the authorization server metadata before the grant | [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) |
| **Dynamic Client Registration** fallback when no `client_id` was persisted; the server-assigned `client_id` is then persisted (refresh tokens are client-bound) | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html) · [OIDC Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html) |
| A registration that issues a **secret** with `token_endpoint_auth_method` **omitted** defaults to `client_secret_basic` | [RFC 7591 §2](https://www.rfc-editor.org/rfc/rfc7591.html#section-2) (default) · [OIDC Registration 1.0 §2](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata) |
| The **WebID** is read from the id_token `webid` claim (Solid-OIDC), falling back to `sub` | [Solid-OIDC](https://solidproject.org/TR/oidc) |
| **`invalid_grant`** = a definitively dead refresh token (cleared); other errors are transient (preserved) | [RFC 6749 §5.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2) |

The heavy lifting (discovery, PKCE, the DPoP proof + nonce handshake, the grant
requests/responses, all client-auth methods) is delegated to **`oauth4webapi`** + the
**`dpop`** package — this repo does not hand-roll OAuth.

### Bespoke — per-server workarounds (deviations from the spec)

These exist **only** because specific Solid servers deviate. Each is narrowly scoped so
it never affects a conformant server.

| Workaround | Why | Scope |
|---|---|---|
| **Inrupt ESS / PodSpaces `client_secret_basic` is sent WITHOUT RFC 6749 §2.3.1 form-url-encoding** — `btoa("client_id:secret")` on the raw values. | ESS (`login.inrupt.com`) **rejects** the spec-encoded form ([RFC 6749 §2.3.1 / App. B](https://www.rfc-editor.org/rfc/rfc6749.html#appendix-B) say the `Basic` userid/password are the `application/x-www-form-urlencoded` client_id/secret). For every **other** issuer the spec-compliant `oauth4webapi.ClientSecretBasic` is used. | Keyed on the discovered issuer's **exact hostname** being `login.inrupt.com` (a look-alike issuer that merely contains the substring is not matched). |
| **Persisting a `client_secret` at all** (for the confidential dynamic path). | Strict OAuth treats a refresh-token grant as a fresh token-endpoint call needing client auth; a closed-tab reopen has no live secret, so to restore a confidential dynamic client we must persist it. A **public** client (the suite's normal config — a static Client Identifier Document) persists no secret and this never applies. | Present only when `tokenEndpointAuthMethod` is confidential. |

Two further server quirks are handled in the **app's login layer**, not in this restore
package (noted here for completeness because they shape what restore consumes):

- **NSS / some ESS variants omit the DPoP `use_dpop_nonce` / id_token `nonce`** — the
  login provider expects-no-nonce for those issuers (e.g. `solidweb.org`,
  `datapod.igrant.io`). Restore inherits a correct session from login and does not
  re-implement this.
- **`prompt=none` silent-auth quirks** (NSS/Trinpod) belong to the interactive login,
  not the refresh-token restore path this package owns.

## The exported CORE API

### `IndexedDbSessionStore` — the durable, issuer-keyed credential store

```ts
const store = new IndexedDbSessionStore({ dbName: "pod-mail:sessions" });
//                                       ↑ unique per app on a shared origin
```

Implements `SessionStore` (`get`/`put`/`delete`, keyed by issuer). Writes resolve on
the transaction **commit** (`tx.oncomplete`), not the request — a credential is
never reported persisted before it is durable. Construct only in the browser; guard
with `indexedDbAvailable()`.

- `PersistedSession` — `{ issuer, webId, refreshToken, dpopKey: CryptoKeyPair, clientId?, tokenEndpointAuthMethod?, clientSecret?, expiresAt? }`
  (no access token, ever). `tokenEndpointAuthMethod` + `clientSecret` are present **only**
  for a confidential client (the ESS/PodSpaces path — see
  [Spec-compliant vs bespoke](#spec-compliant-vs-bespoke-per-server)); a public client
  persists neither.
- `TokenEndpointAuthMethod` — `"none" | "client_secret_basic" | "client_secret_post"`.
- `SessionStore` — the injectable contract (supply an in-memory double in tests).
- `DEFAULT_DB_NAME`, `IndexedDbSessionStoreOptions`, `indexedDbAvailable()`.

### `RememberedAccount` — the credential-free WebID→issuer pointer

```ts
const remembered = new RememberedAccount("pod-mail.remembered-account");
remembered.write(webId, issuer); // on login
remembered.read();               // { webId, issuer? } | null — on load
remembered.clear();              // on logout / account change
```

Backed by localStorage under an **app-specific key**. Holds **no credential** — only
the public WebID + issuer URL. Degrades safely (private mode / SSR / quota → "no
remembered account", never a throw).

- `RememberedAccountRecord` — `{ webId, issuer? }`.
- `DEFAULT_REMEMBERED_ACCOUNT_KEY`.

### `decideSilentRestore` / `shouldDropRememberedPointer` — the PURE decision

```ts
const decision = await decideSilentRestore({
  lastActiveWebId: remembered?.webId,
  remembered: remembered ? [remembered] : [],
  restoreIssuer: (issuer) => provider.restoreIssuer(new URL(issuer)),
  webIdsEqual, // optional — defaults to the package's webIdsEqual
});
// → { outcome: "restored", webId, issuer }
// | { outcome: "login", reason: "no-account" | "no-issuer" | "restore-failed" | "webid-mismatch" }
```

Pure except for the injected `restoreIssuer` (the one fetch). Never throws (a thrown
restore is treated as `login` / `restore-failed`, fail-closed). The branch table and
the WebID-scoped isolation are exhaustively tested.

```ts
// After a `login` decision, decide whether to drop the pointer:
shouldDropRememberedPointer(reason, credentialPresence); // "present" | "absent" | "unknown"
```

- `SessionRestoreDecision`, `LoginReason`, `RestoreIssuer`, `SilentRestoreInputs`,
  `CredentialPresence`, `webIdsEqual`.

### `restoreSession` — the DPoP-bound refresh-token-grant restore

```ts
const restored = await restoreSession({
  store,                  // the SessionStore
  issuer: new URL(iss),   // the remembered issuer
  clientId,               // your Solid-OIDC Client Identifier Document URL (or omit → dynamic reg)
  clientSecret,           // OPTIONAL — confidential-client secret (ESS/PodSpaces); omit for a public client
  tokenEndpointAuthMethod,// OPTIONAL — "none" (default) | "client_secret_basic" | "client_secret_post"
  allowInsecureLoopback,  // true only for localhost dev CSS over HTTP
  signal,                 // optional AbortSignal
  fetch,                  // optional fetch override
});
// → RestoredSession { webId, accessToken, refreshToken, dpopKey, dpopHandle, expiresAt, issuer }
// | undefined  (nothing to restore / dead token [cleared] / transient failure [preserved] /
//              confidential method with no secret [preserved, fail-closed])
```

Discovers the AS, **re-attaches the persisted non-extractable DPoP key**, runs the
`refresh_token` grant (one retry on a server DPoP-nonce challenge), re-persists the
**rotated** token, and returns the rebuilt session. Reuses `oauth4webapi` + `dpop`.

A refresh token is **client-bound** (RFC 6749 §6), so the grant runs as the original
client: `clientId` if you pass one, else the `clientId` the login **persisted** into
the session record (for the dynamic-registration path, the server-assigned id). A
fresh dynamic registration is performed **only** when neither is available — a brand
new client cannot redeem a previously-issued refresh token.

**Client authentication** (RFC 6749 §2.3 / OIDC Core §9) defaults to `none` (a
**public** client — static Client Identifier Document / PKCE, no secret), exactly as
before. A **confidential** client — one whose login persisted a `clientSecret` +
`tokenEndpointAuthMethod` of `client_secret_basic` / `client_secret_post`, or a fresh
dynamic registration that came back confidential (the **ESS/PodSpaces** path) — presents
that secret on the grant, and the resolved secret + method are re-persisted across
rotation so the next reload authenticates the same way. The secret is stored under the
same WebID/issuer-scoped IndexedDB discipline as the refresh token (fail-closed; cleared
on logout) and **never logged**. If a confidential method is set but **no secret** is
available, restore **fails closed** (returns `undefined`, preserving the credential) —
it never silently downgrades to `none`. See
[Spec-compliant vs bespoke](#spec-compliant-vs-bespoke-per-server) for exactly which of
this is standard OIDC vs a per-server workaround.

- `RestoredSession`, `RestoreSessionOptions`.
- Lifecycle: `forgetPersisted(store, issuer)` / `clearPersisted(store, issuer)`
  (logout), `hasPersisted(store, issuer)` (tri-state: `present`/`absent`/`unknown`),
  `isInvalidGrantError(e)` (the dead-vs-transient classifier).

### `toAuthenticatedFetch` — a DPoP-authenticated `fetch` from a restored session

Turn a `RestoredSession` into a standard `fetch` whose every request carries
`Authorization: DPoP <accessToken>` plus a **fresh per-request DPoP proof** signed by the
session's bound (non-extractable) key — so apps stop hand-rolling the auth-attaching pod
fetch and share **one** audited implementation (it was extracted from the elk fork's
`authedFetchFromRestoredSession`).

```ts
const restored = await restoreSession({ store, issuer, clientId });
if (!restored) return; // logged-out, no popup

const authedFetch = toAuthenticatedFetch(restored, {
  // OPTIONAL — silently re-mint a fresh access token on a 401 (token-endpoint fetch, no popup).
  refresh: async () => restoreSession({ store, issuer, clientId }),
  // OPTIONAL — the underlying fetch to transport bytes (default global fetch); a hook for an
  // SSRF-guarded fetch or the reactive-auth patched global. DPoP auth is attached regardless.
  fetch: myFetch,
  // OPTIONAL — allow http:// for localhost/127.0.0.1/[::1] only (dev CSS). Default false.
  allowInsecureLoopback: false,
});

// Use it like any fetch — every pod request is DPoP-authenticated.
const res = await authedFetch("https://alice.example/private/notes");
```

The proof, the `Authorization` header, and the server **DPoP-nonce** handshake are all
delegated to `oauth4webapi`'s `protectedResourceRequest` (driven by the session's
`dpopHandle`) — **never** a hand-rolled proof. Bounded retries: one DPoP-nonce retry
(RFC 9449 §8) **and** — when `refresh` is supplied — one token-refresh retry on a 401
(both a thrown `invalid_token` challenge and a returned bare-401 are caught), after which
the fresh credential is adopted for subsequent requests too. A failed/absent `refresh`,
or a second 401 after a fresh token, surfaces the 401 rather than looping (**fail-closed**).
A caller-supplied `Authorization`/`DPoP` header on the request is **stripped** so it cannot
pin a foreign credential. The returned fetch is bound to **one** session's credential — on
a user switch / logout, build a new authed fetch and drop the old one (this helper does not
own that lifecycle).

- `toAuthenticatedFetch(session, options?)`, `ToAuthenticatedFetchOptions`,
  `RefreshAuthenticatedFetch`, `AuthenticatedFetchCredential` (the
  `Pick<RestoredSession, "accessToken" | "dpopHandle">` a `refresh` returns).

## The thin per-app wiring (what each app keeps)

The package is the **CORE**; the per-app wiring is small and stays in each app
(it is framework-specific — React/Solid context, an `<authorization-code-flow>` /
the suite's token provider). Two pieces:

### 1. The token-provider restore method

The app's `WebIdDPoPTokenProvider` keeps a **thin `restoreIssuer(issuer)`** that
calls `restoreSession(...)` and then pins the result into its own in-memory state
(so a later 401 upgrade reuses the restored session with no re-prompt), under its
generation/reset fence:

```ts
async restoreIssuer(issuer: URL): Promise<{ webId: string } | undefined> {
  const generation = this.#generation;
  const restored = await restoreSession({
    store: this.#sessionStore,
    issuer,
    clientId: this.#clientId,
    allowInsecureLoopback: this.#allowInsecureLoopback,
    signal: this.#authController.signal,
  });
  if (!restored) return undefined;
  // FENCE: a reset() (logout / new login) during the grant supersedes this restore.
  if (generation !== this.#generation) return undefined;
  this.#sessions.set(issuer.href, Promise.resolve(toIssuerSession(restored)));
  this.#issuer = Promise.resolve(issuer);          // pin, like the popup login
  this.#authenticatedWebId = restored.webId;
  return { webId: restored.webId };
}
// logout → forgetPersisted(this.#sessionStore, issuer)
// keep/drop decision → hasPersisted(this.#sessionStore, issuer)
```

### 2. The mount-time `runSilentRestore` effect

The provider/session context runs **once on mount**, before deciding "logged out",
gated so an explicit autologin deep-link / redirect return takes precedence:

```ts
async function runSilentRestore(provider, remembered /* RememberedAccount */) {
  const r = remembered.read();
  const decision = await decideSilentRestore({
    lastActiveWebId: r?.webId,
    remembered: r ? [r] : [],
    restoreIssuer: (issuer) => provider.restoreIssuer(new URL(issuer)),
    webIdsEqual,
  });
  if (decision.outcome === "restored") {
    remembered.write(decision.webId, decision.issuer); // re-confirm the pointer
    return { kind: "restored", webId: decision.webId, issuer: decision.issuer };
  }
  // webid-mismatch: restoreSession already pinned+persisted the WRONG WebID one
  // layer down — tear down fail-closed, in this order:
  if (decision.reason === "webid-mismatch") {
    provider.reset();                                   // 1. drop the in-memory session FIRST
    if (r?.issuer) await forgetPersisted(store, new URL(r.issuer)); // 2. drop the durable credential
    remembered.clear();
    return { kind: "login" };
  }
  // else: keep/drop the pointer per the pure matrix + the tri-state presence.
  const presence = r?.issuer ? await hasPersisted(store, new URL(r.issuer)) : "absent";
  if (shouldDropRememberedPointer(decision.reason, presence)) remembered.clear();
  return { kind: "login" };
}
```

Single-flight it (cache the promise) so React StrictMode / concurrent mounts run it
once, and paint a brief "Restoring…" state while it resolves rather than flashing the
login form. A **restored** token means logged-in even if the cosmetic profile read
later fails (load the profile separately and let it degrade).

> The app also keeps: generating the **non-extractable** ES256 DPoP key at login and
> requesting `offline_access` (so a refresh token is issued), and calling
> `store.put(...)` / `forgetPersisted(...)` from its login / logout paths. This
> package owns the *restore*; the app owns the *login that produces what restore
> consumes*.

## Migration recipe — switch a vite pod-app from copy → package

For each of the 7 apps (`pod-mail`, `pod-music`, `pod-photos`, `pod-drive`,
`pod-money`, `pod-health`, `pod-chat` — and `pod-docs`):

1. **Add the dep** (buildless GitHub install):
   ```bash
   npm install github:jeswr/solid-session-restore#main --prefer-offline --no-audit --no-fund
   ```
2. **Delete the copied modules** from `web/src/auth/`:
   `session-persistence.ts`, `remembered-account.ts`, `session-restore.ts`
   (and their `*.test.ts` — the package owns those tests now).
3. **Re-point imports** to the package:
   - `IndexedDbSessionStore` — construct with the app's DB name:
     `new IndexedDbSessionStore({ dbName: "pod-mail:sessions" })` (was the hard-coded
     `"pod-mail:sessions"` constant).
   - the `readRememberedAccount` / `writeRememberedAccount` / `clearRememberedAccount`
     module functions → a `new RememberedAccount("pod-mail.remembered-account")`
     instance's `.read()` / `.write()` / `.clear()` (same per-app key string).
   - `decideSilentRestore`, `shouldDropRememberedPointer`, `webIdsEqual`,
     `PersistedSession`, `SessionStore`, `RememberedAccount` type
     (`RememberedAccountRecord`), `CredentialPresence`, `LoginReason` — from the
     package.
4. **Replace the provider's restore internals** with a thin wrapper over
   `restoreSession` / `forgetPersisted` / `hasPersisted` (see "thin per-app wiring"
   above). Keep the provider's generation/reset fence and its login/logout
   `store.put` / `forgetPersisted` calls.
5. **Gate:** `npm run lint && npm run typecheck && npm test && npm run build`. The
   app's remaining provider/SessionProvider tests should pass unchanged (the seams
   are identical); the deleted modules' tests are now the package's.

**pod-mail (the pilot)** is the reference: do it first, confirm parity (silent
restore on reopen still works against a local CSS), then the other six follow the
identical edit. Because pod-mail's modules were the source for this package, its
behaviour is bit-for-bit preserved (the one generalisation — injectable DB
name/storage key — is supplied with pod-mail's existing string constants).

## Gate

```bash
npm run gate   # lint (biome) + typecheck (tsc) + test (vitest) + build + check:dist
```

## License

MIT © Jesse Wright
