// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// restore-session.ts — the DPoP-bound `refresh_token` grant that rebuilds a
// returning user's Solid-OIDC session from the persisted, sender-constrained
// refresh token. A token-endpoint FETCH only — never a popup/iframe.
//
// Extracted from the pod-mail pilot's WebIdDPoPTokenProvider (#restore / #refresh /
// restoreIssuer / forgetPersisted / hasPersisted), collapsed into a STANDALONE
// helper so the 7 vite pod-apps share ONE audited implementation. The per-app
// token provider keeps a THIN wrapper that calls this and pins the issuer/session
// in its own in-memory state (see the README "thin per-app wiring").
//
// ─── Security invariants (do not weaken — this redeems a credential) ─────────
//  • DPoP-BOUND, not bare Bearer: the refresh grant carries a DPoP handle built
//    around the PERSISTED key, so the proof is signed by the SAME key the token was
//    sender-constrained to (RFC 9449 §4.3). A stolen refresh token is useless
//    without that non-extractable key.
//  • ASYMMETRIC-ONLY: the persisted DPoP key is an ES256 (P-256 ECDSA) key pair;
//    the grant never falls back to a symmetric/bearer proof.
//  • CLEAR ONLY ON DEFINITIVE `invalid_grant`: a dead refresh token (expired /
//    revoked / rotation-reuse) is cleared so a doomed restore is not retried. A
//    TRANSIENT failure (network / discovery 5xx / abort) PRESERVES the credential —
//    a blip on load must not force a needless re-login.
//  • FAIL-CLOSED: every "nothing to restore / could not rebuild" path returns
//    `undefined` (the caller falls back to login). The helper never throws for the
//    normal absent/dead-token case.
//  • ROTATION: when the server rotates the refresh token (RFC 9700 §4.14.2), the
//    NEW token is re-persisted so the next reload uses the current credential.
//  • The ACCESS TOKEN is never persisted; the refresh token is never logged.
//  • PUBLIC by DEFAULT, CONFIDENTIAL only when a secret is present: the grant uses
//    `none` client auth (RFC 6749 §2.3 / OIDC Core §9) unless the session is a
//    CONFIDENTIAL client (a persisted `client_secret` + `client_secret_basic`/
//    `client_secret_post` method — the ESS/PodSpaces dynamic-registration path), in
//    which case the secret is presented per the persisted method. The secret is
//    NEVER logged and is cleared with the rest of the credential on logout. This is
//    additive: a static Client Identifier Document / PKCE client persists no secret
//    and behaves exactly as before (`none`).
import * as oauth from "oauth4webapi";
/** Refresh this much before the reported expiry to absorb clock skew. */
const EXPIRY_SKEW_MS = 30_000;
const isLoopback = (host) => host === "localhost" || host === "127.0.0.1" || host === "[::1]";
/** Epoch ms the access token should be treated as expired, or undefined when none reported. */
function expiresAtFrom(token) {
    return token.expires_in === undefined
        ? undefined
        : Date.now() + token.expires_in * 1000 - EXPIRY_SKEW_MS;
}
/**
 * The WebID an id_token authenticated AS. Solid-OIDC carries the WebID in the
 * `webid` claim; when absent (some servers put it in `sub`), `sub` is the WebID.
 * Returns undefined when neither is a usable string.
 */
function webIdFromClaims(claims) {
    if (!claims)
        return undefined;
    const webid = claims.webid;
    if (typeof webid === "string" && webid.length > 0)
        return webid;
    if (typeof claims.sub === "string" && claims.sub.length > 0)
        return claims.sub;
    return undefined;
}
/**
 * Whether a refresh-grant error is a DEFINITIVE `invalid_grant` — the refresh
 * token is expired / revoked / rotation-reuse-detected, so it is dead and the
 * persisted entry should be cleared. oauth4webapi surfaces a token-endpoint OAuth
 * error as a `ResponseBodyError` carrying an `error` field; we read that
 * structurally (an instanceof can be brittle across module/bundle boundaries) and
 * also accept an `error` nested under `.cause.parameters` (the shape some flows
 * wrap it in). Any OTHER failure (network, discovery 5xx, abort) returns false, so
 * a transient blip on load does NOT erase an otherwise-valid credential.
 */
export function isInvalidGrantError(e) {
    if (e && typeof e === "object") {
        const err = e;
        if (err.error === "invalid_grant")
            return true;
        try {
            if (err.cause?.parameters?.get("error") === "invalid_grant")
                return true;
        }
        catch {
            // .cause.parameters not a URLSearchParams — not the shape we handle.
        }
    }
    return false;
}
/** Build the oauth4webapi HTTP options (signal + loopback-only insecure allowance). */
function httpOptions(issuer, options) {
    const out = {};
    if (options.signal)
        out.signal = options.signal;
    if (options.fetch) {
        const appFetch = options.fetch;
        // oauth4webapi invokes customFetch with `(url, options)` where `options` is a
        // superset of RequestInit it constructed — pass it straight to the app's fetch
        // (runtime-compatible). The DOM `fetch` accepts `RequestInit`.
        out[oauth.customFetch] = (url, opts) => appFetch(url, opts);
    }
    if (options.allowInsecureLoopback && isLoopback(issuer.hostname)) {
        out[oauth.allowInsecureRequests] = true;
    }
    return out;
}
/** Discover the authorization server metadata for an issuer. */
async function discover(issuer, http) {
    const discoveryResponse = await oauth.discoveryRequest(issuer, http);
    return oauth.processDiscoveryResponse(issuer, discoveryResponse);
}
/** Whether a method actually requires a secret (a confidential method). */
function isConfidentialMethod(method) {
    return method === "client_secret_basic" || method === "client_secret_post";
}
/**
 * Whether a token-endpoint auth method is one this package SUPPORTS — exactly
 * `none` / `client_secret_basic` / `client_secret_post`. Any other defined value
 * (e.g. `client_secret_jwt`, `private_key_jwt`, `tls_client_auth`) is unsupported,
 * and an unsupported method must FAIL CLOSED rather than silently downgrade to `none`
 * (roborev finding). Accepts an unknown string because the value can come from a
 * persisted record / option / server registration response.
 */
function isSupportedMethod(method) {
    return method === "none" || method === "client_secret_basic" || method === "client_secret_post";
}
/**
 * Resolve the OAuth client a refresh grant must run as, AND how it authenticates. A
 * refresh token is CLIENT-BOUND (RFC 6749 §6 / §10.4): it can only be redeemed by
 * the same client that obtained it. So we reuse the original client identity —
 * `options.clientId` (the app's static Client Identifier Document URL, if it used
 * one) OR the `clientId` the original login PERSISTED into the session record (which,
 * for the dynamic-registration path, is the server-assigned `client_id`). We perform
 * a FRESH dynamic registration ONLY when neither is available — a brand-new client
 * has no claim to a previously-issued refresh token, so reusing the stored id is
 * what keeps a dynamic-login user restorable instead of failing `invalid_client`
 * (roborev finding).
 *
 * CLIENT AUTH (RFC 6749 §2.3 / OIDC Core §9): a static Client Identifier Document /
 * PKCE client is PUBLIC → `none` (no secret), as before. A CONFIDENTIAL client —
 * persisted (or option-supplied) with a `client_secret` + a
 * `client_secret_basic`/`client_secret_post` method (the rare ESS/PodSpaces dynamic
 * path) — presents that secret. The method/secret are resolved with OPTION-OVER-
 * PERSISTED precedence; a fresh dynamic registration adopts whatever the server
 * returns. The DPoP-binding still authorises the grant regardless — the client
 * secret is the SECOND factor some servers additionally require.
 */
async function resolveClient(authorizationServer, options, stored, http) {
    const clientId = options.clientId ?? stored.clientId;
    // Option overrides persisted; default `none` (public client) when neither set. The
    // value can come from a persisted record / option, so VALIDATE it (it is typed but a
    // store could hold any string): an UNSUPPORTED method (client_secret_jwt /
    // private_key_jwt / tls_client_auth) must fail closed, not silently downgrade to
    // `none` — same fail-closed rule the fresh-registration path uses (roborev finding).
    const requestedMethod = options.tokenEndpointAuthMethod ?? stored.tokenEndpointAuthMethod;
    const supported = requestedMethod === undefined || isSupportedMethod(requestedMethod);
    const authMethod = supported
        ? (requestedMethod ?? "none")
        : "client_secret_basic"; // sentinel; unsupported→true makes buildClientAuth fail closed
    const secret = options.clientSecret ?? stored.clientSecret;
    if (clientId !== undefined && clientId !== "") {
        return {
            client: {
                client_id: clientId,
                token_endpoint_auth_method: authMethod,
                ...(options.callbackUri ? { redirect_uris: [options.callbackUri] } : {}),
                response_types: ["code"],
            },
            authMethod,
            secret: supported && isConfidentialMethod(authMethod) ? secret : undefined,
            unsupported: !supported,
        };
    }
    // No persisted/static client id — fall back to a fresh dynamic registration. This
    // only succeeds against servers whose refresh tokens are not strictly bound to the
    // original registration; it is the best available behaviour for the rare case of a
    // dynamic login that never persisted its client id. Adopt whatever client-auth the
    // server registers us with (it may be `client_secret_basic` — the ESS case).
    const registrationResponse = await oauth.dynamicClientRegistrationRequest(authorizationServer, options.callbackUri ? { redirect_uris: [options.callbackUri] } : {}, http);
    const registered = await oauth.processDynamicClientRegistrationResponse(registrationResponse);
    // The registration metadata is loosely typed (any JSON value); coerce the method to
    // a string-or-undefined before validating, so a non-string value is treated as
    // "no usable method" (→ the omitted/default path), never crashes the type check.
    const registeredMethod = typeof registered.token_endpoint_auth_method === "string"
        ? registered.token_endpoint_auth_method
        : undefined;
    const freshSecret = typeof registered.client_secret === "string" && registered.client_secret !== ""
        ? registered.client_secret
        : undefined;
    // Resolve the fresh registration's client-auth method, defaulting per OIDC/RFC 7591:
    //  • method OMITTED → `client_secret_basic` if a secret was issued (RFC 7591 §2 /
    //    OIDC Registration 1.0 default; treating it as `none` would skip required auth),
    //    else `none` (a public client, as before);
    //  • a supported method (none / client_secret_basic / client_secret_post) → adopt it;
    //  • ANY OTHER defined method (client_secret_jwt / private_key_jwt / tls_client_auth)
    //    → UNSUPPORTED: FAIL CLOSED — model it as a confidential method with NO usable
    //    secret so {@link buildClientAuth} returns undefined and the restore aborts. We
    //    must never silently send `none` (mis-auth) to a server that registered us with a
    //    stronger method, whether or not a secret was also issued (roborev finding).
    const effectiveMethod = registeredMethod ?? (freshSecret !== undefined ? "client_secret_basic" : "none");
    const freshSupported = isSupportedMethod(effectiveMethod);
    const freshMethod = freshSupported
        ? effectiveMethod
        : "client_secret_basic"; // sentinel; unsupported→true fails closed in buildClientAuth
    return {
        client: registered,
        authMethod: freshMethod,
        secret: freshSupported && isConfidentialMethod(freshMethod) ? freshSecret : undefined,
        unsupported: !freshSupported,
    };
}
/**
 * A variant of oauth4webapi's {@link oauth.ClientSecretBasic} that does NOT
 * URL-encode the client_id / secret before base64. PodSpaces (Inrupt ESS) rejects
 * the spec-compliant `application/x-www-form-urlencoded` form (RFC 6749 §2.3.1 /
 * Appendix B) and expects the raw values — this is a BESPOKE per-server workaround,
 * scoped to ESS issuers only. The standard, spec-following encoder is used for every
 * other server.
 *
 * @see https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1
 */
function noUrlEncodeClientSecretBasic(clientSecret) {
    return (_as, client, _body, headers) => {
        headers.set("authorization", `Basic ${btoa(`${client.client_id}:${clientSecret}`)}`);
    };
}
/** The ESS host whose token endpoint rejects the spec form-url-encoded Basic creds. */
const ESS_NO_URL_ENCODE_HOST = "login.inrupt.com";
/**
 * Whether an issuer is the Inrupt ESS host that needs the no-url-encode workaround,
 * matched on the EXACT hostname (an unparseable issuer → false, so we never apply the
 * bespoke path to an unknown issuer). This is stricter than the pod-mail provider's
 * substring `includes` — an exact host match cannot be tricked by an unrelated issuer
 * whose URL merely CONTAINS the substring (e.g. a path/subdomain), which would
 * otherwise send a non-standard Basic header to the wrong server (roborev finding).
 */
function isEssNoUrlEncodeIssuer(issuer) {
    try {
        return new URL(issuer).hostname === ESS_NO_URL_ENCODE_HOST;
    }
    catch {
        return false;
    }
}
/**
 * Pick the `client_secret_basic` constructor for an issuer: the BESPOKE
 * non-URL-encoding variant for Inrupt ESS (`login.inrupt.com`) — which rejects the
 * spec encoding — and the standard, RFC-6749-§2.3.1-compliant
 * {@link oauth.ClientSecretBasic} for every other server. Mirrors the pod-mail
 * provider's `clientSecretBasicFor` (hardened to an exact-hostname match).
 */
function clientSecretBasicFor(issuer) {
    return isEssNoUrlEncodeIssuer(issuer) ? noUrlEncodeClientSecretBasic : oauth.ClientSecretBasic;
}
/**
 * Build the oauth4webapi {@link oauth.ClientAuth} for a resolved client. PUBLIC
 * clients → `none` (RFC 6749 §2.3, no secret). CONFIDENTIAL clients present their
 * secret per the resolved method (RFC 6749 §2.3.1 / OIDC Core §9):
 * `client_secret_basic` via the Basic header (with the ESS no-URL-encode workaround),
 * `client_secret_post` via the form body. Returns `undefined` — a FAIL-CLOSED signal
 * — when (a) the resolved method is a defined but UNSUPPORTED one, or (b) a confidential
 * method was resolved but NO secret is available: we must NOT silently downgrade to
 * `none` (that would mis-authenticate, and on some servers succeed-as-public when the
 * user intended a confidential client), so the caller aborts the restore instead.
 */
function buildClientAuth(issuer, resolved) {
    if (resolved.unsupported)
        return undefined; // fail-closed: unsupported auth method
    if (!isConfidentialMethod(resolved.authMethod))
        return oauth.None();
    const secret = resolved.secret;
    if (secret === undefined || secret === "")
        return undefined; // fail-closed: no secret
    return resolved.authMethod === "client_secret_post"
        ? oauth.ClientSecretPost(secret)
        : clientSecretBasicFor(issuer)(secret);
}
/**
 * The refresh-token grant (RFC 6749 §6), DPoP-bound with the supplied key/handle and
 * authenticated with the supplied client-auth, adopting the rotated refresh token
 * when the server issues one. One retry on a server-required DPoP nonce (the handle
 * captures it from the error).
 */
async function refreshGrant(authorizationServer, clientRegistration, clientAuth, dpopHandle, refreshToken, http) {
    const grant = () => oauth.refreshTokenGrantRequest(authorizationServer, clientRegistration, clientAuth, refreshToken, { DPoP: dpopHandle, ...http });
    try {
        return await oauth.processRefreshTokenResponse(authorizationServer, clientRegistration, await grant());
    }
    catch (e) {
        if (!oauth.isDPoPNonceError(e))
            throw e;
        // The handle captured the server's DPoP nonce from the error; retry once.
        return await oauth.processRefreshTokenResponse(authorizationServer, clientRegistration, await grant());
    }
}
/**
 * Re-persist the ROTATED refresh-token session so the NEXT reload restores from the
 * CURRENT credential, not a spent one (servers rotate refresh tokens — RFC 9700
 * §4.14.2). The persisted record carries forward the RESOLVED `clientId` — the
 * persisted/static one, or (for a fresh dynamic registration that had none) the
 * SERVER-ASSIGNED id — so the refresh token stays client-bound (RFC 6749 §6 / §10.4)
 * and the next reload reuses the same client instead of re-registering; plus the
 * advisory `expiresAt`, and — for a CONFIDENTIAL client — the resolved
 * `tokenEndpointAuthMethod` + `clientSecret` (so the NEXT reload can authenticate the
 * grant the same way, incl. a secret first seen on this load's fresh dynamic
 * registration). The access token is NEVER persisted.
 *
 * BEST-EFFORT and SELF-CONTAINED: it swallows its own store-write error so a failed
 * re-persist can never (a) fail an otherwise-good restore, nor (b) escape to
 * {@link restoreSession}'s outer catch, where a write fault would be misclassified
 * against `invalid_grant`. A failed re-persist leaves THIS load's in-memory session
 * valid; the next reload may re-prompt. Never logged.
 */
async function persistRotatedSession(store, issuer, stored, restored, resolved) {
    // Carry the CONFIDENTIAL credentials forward ONLY when the grant actually used a
    // confidential method WITH a secret — never persist `none`/an empty secret, so a
    // public client's record stays secret-free. Capture the narrowed secret into a
    // local (a non-empty string here) so the spread satisfies exactOptionalPropertyTypes.
    const secret = resolved.secret;
    const confidential = isConfidentialMethod(resolved.authMethod) && secret !== undefined && secret !== "";
    // PRESERVE the client_id the grant ACTUALLY ran as so the next reload reuses the SAME
    // client (a refresh token is client-bound — RFC 6749 §6 / §10.4). Prefer the RESOLVED
    // client_id over the stored one: when `options.clientId` overrode a stale persisted id
    // (or a fresh dynamic registration ran), the rotated refresh token was issued to the
    // RESOLVED client, so persisting the stale stored id would let a later restore redeem
    // it as the WRONG client (roborev finding). Fall back to the (normalised, non-empty)
    // stored id only if the resolved client somehow carries none.
    const resolvedClientId = typeof resolved.client.client_id === "string" && resolved.client.client_id !== ""
        ? resolved.client.client_id
        : undefined;
    const persistedClientId = stored.clientId !== undefined && stored.clientId !== "" ? stored.clientId : undefined;
    const clientId = resolvedClientId ?? persistedClientId;
    try {
        await store.put({
            issuer: issuer.href,
            webId: restored.webId,
            refreshToken: restored.refreshToken,
            dpopKey: stored.dpopKey,
            ...(clientId !== undefined ? { clientId } : {}),
            ...(confidential
                ? {
                    tokenEndpointAuthMethod: resolved.authMethod,
                    clientSecret: secret,
                }
                : {}),
            ...(restored.expiresAt !== undefined ? { expiresAt: restored.expiresAt } : {}),
        });
    }
    catch {
        // Durable re-persistence failed — see the doc comment. Non-fatal, never logged.
    }
}
/**
 * RESTORE a returning user's session for a KNOWN issuer from the durable store via
 * a `refresh_token` grant — a token-endpoint FETCH, never a window/iframe.
 *
 * Returns the rebuilt {@link RestoredSession} on success (the rotated credential is
 * already re-persisted), or `undefined` when:
 *   • the store is unreadable / has no entry / the entry has no refresh token; OR
 *   • the persisted refresh token is dead — in which case the dead entry is CLEARED
 *     (a definitive `invalid_grant` only); a TRANSIENT failure returns undefined but
 *     PRESERVES the credential for a later retry.
 *
 * Fail-closed: never throws for the normal absent/dead-token path. The DPoP key is
 * re-attached from the persisted record (key continuity — the proof is signed by the
 * key the token is bound to).
 */
export async function restoreSession(options) {
    const { store, issuer } = options;
    let stored;
    try {
        stored = await store.get(issuer.href);
    }
    catch {
        return undefined; // store unreadable — nothing to restore, stay silent.
    }
    if (stored === undefined || stored.refreshToken === undefined || stored.refreshToken === "") {
        return undefined;
    }
    try {
        const http = httpOptions(issuer, options);
        const authorizationServer = await discover(issuer, http);
        const resolved = await resolveClient(authorizationServer, options, stored, http);
        const clientRegistration = resolved.client;
        // Build the client authentication (RFC 6749 §2.3 / OIDC Core §9): `none` for a
        // PUBLIC client, the persisted/resolved secret for a CONFIDENTIAL one. A
        // confidential method with NO secret yields `undefined` — FAIL CLOSED rather than
        // silently downgrade to `none` (which could mis-authenticate the client). Treated
        // like a transient failure: the credential is PRESERVED (it is not proof the
        // refresh token itself is dead), and this load falls back to login.
        const clientAuth = buildClientAuth(authorizationServer.issuer, resolved);
        if (clientAuth === undefined)
            return undefined;
        // Reattach the PERSISTED, non-extractable DPoP key — the refresh-grant proof
        // must be signed by the key the token is bound to (RFC 9449 §4.3).
        const dpopHandle = oauth.DPoP(clientRegistration, stored.dpopKey);
        const tokenResult = await refreshGrant(authorizationServer, clientRegistration, clientAuth, dpopHandle, stored.refreshToken, http);
        // Adopt the rotated refresh token when the server issues one; keep the old one
        // otherwise (some servers do not rotate).
        const refreshToken = tokenResult.refresh_token ?? stored.refreshToken;
        // Prefer the id_token's WebID when the refresh response carries one; else keep
        // the WebID the persisted session authenticated AS originally.
        const webId = webIdFromClaims(oauth.getValidatedIdTokenClaims(tokenResult)) ?? stored.webId;
        const restored = {
            webId,
            accessToken: tokenResult.access_token,
            refreshToken,
            dpopKey: stored.dpopKey,
            dpopHandle,
            expiresAt: expiresAtFrom(tokenResult),
            issuer: issuer.href,
        };
        // Re-persist the rotated credential (best-effort; self-contained — see the helper),
        // carrying forward the resolved confidential-client auth (method + secret) so the
        // next reload authenticates the grant the same way.
        await persistRotatedSession(store, issuer, stored, restored, resolved);
        return restored;
    }
    catch (e) {
        // Distinguish a DEFINITIVELY DEAD refresh token from a TRANSIENT failure: only
        // `invalid_grant` means the credential is gone — clear it so a doomed restore
        // is not re-attempted. A transient discovery/network/server error on page load
        // must NOT erase an otherwise-valid refresh token. Either way report "nothing
        // restored" so the caller falls back to login silently (no popup on restore).
        if (isInvalidGrantError(e))
            await clearPersisted(store, issuer);
        return undefined;
    }
}
/**
 * Drop the durable session for an issuer (explicit logout / dead refresh token).
 * Idempotent; swallows store errors (a stale entry is harmless — its refresh token
 * is DPoP-bound, and a failed restore re-clears it).
 */
export async function clearPersisted(store, issuer) {
    try {
        await store.delete(issuer.href);
    }
    catch {
        // Non-fatal.
    }
}
/** Alias for {@link clearPersisted} reading as the logout-side call. */
export const forgetPersisted = clearPersisted;
/**
 * Whether a durable refresh-token session is STILL persisted for this issuer — a
 * TRI-STATE so the caller can distinguish "definitely gone" from "couldn't tell":
 *  - `"present"` — a credential exists (a transient restore failure preserved it);
 *                   KEEP the remembered pointer to retry on the next load.
 *  - `"absent"`  — no credential (a definitive invalid_grant cleared it, or there
 *                   never was one); the pointer can be dropped.
 *  - `"unknown"` — the store read FAILED (transient IndexedDB error). Do NOT treat
 *                   this as absent — the credential may well be intact, so the caller
 *                   KEEPS the pointer (a kept pointer at worst costs one extra doomed
 *                   restore next load; dropping it could orphan a valid credential).
 */
export async function hasPersisted(store, issuer) {
    try {
        return (await store.get(issuer.href)) !== undefined ? "present" : "absent";
    }
    catch {
        return "unknown";
    }
}
//# sourceMappingURL=restore-session.js.map