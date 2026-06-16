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
- **No access token persisted; the refresh token is never logged.** Only the
  long-lived, key-bound credential is durable.
- **Per-app store + pointer.** The IndexedDB DB name and the localStorage key are
  **injectable** per app, so two apps on a shared origin never share a session store
  or a pointer.

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

- `PersistedSession` — `{ issuer, webId, refreshToken, dpopKey: CryptoKeyPair, clientId?, expiresAt? }`
  (no access token, ever).
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
  store,                 // the SessionStore
  issuer: new URL(iss),  // the remembered issuer
  clientId,              // your Solid-OIDC Client Identifier Document URL (or omit → dynamic reg)
  allowInsecureLoopback, // true only for localhost dev CSS over HTTP
  signal,                // optional AbortSignal
  fetch,                 // optional fetch override
});
// → RestoredSession { webId, accessToken, refreshToken, dpopKey, dpopHandle, expiresAt, issuer }
// | undefined  (nothing to restore / dead token [cleared] / transient failure [preserved])
```

Discovers the AS, **re-attaches the persisted non-extractable DPoP key**, runs the
`refresh_token` grant (one retry on a server DPoP-nonce challenge), re-persists the
**rotated** token, and returns the rebuilt session. Reuses `oauth4webapi` + `dpop`.

- `RestoredSession`, `RestoreSessionOptions`.
- Lifecycle: `forgetPersisted(store, issuer)` / `clearPersisted(store, issuer)`
  (logout), `hasPersisted(store, issuer)` (tri-state: `present`/`absent`/`unknown`),
  `isInvalidGrantError(e)` (the dead-vs-transient classifier).

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
