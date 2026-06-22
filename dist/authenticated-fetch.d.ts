import type { RestoredSession } from "./restore-session.js";
/**
 * The live DPoP credential a request actually sends with: the access token plus the
 * oauth4webapi DPoP handle bound to the session's non-extractable key. A
 * {@link RestoredSession} is a superset of this; {@link toAuthenticatedFetch} reads only
 * these two fields per request, and a {@link RefreshAuthenticatedFetch} re-mints them.
 */
export type AuthenticatedFetchCredential = Pick<RestoredSession, "accessToken" | "dpopHandle">;
/**
 * A SILENT re-mint of the live credential, called ONCE when a request gets a 401
 * (expired/invalid access token). Returns a fresh {@link AuthenticatedFetchCredential}
 * (a full {@link RestoredSession} satisfies it), or `null`/`undefined` when the refresh
 * itself fails (dead/revoked refresh token, transient blip) so the fetch fails closed
 * rather than looping. Typically wraps {@link restoreSession} bound to the same
 * store/issuer/clientId — a token-endpoint fetch, NEVER a popup/iframe.
 */
export type RefreshAuthenticatedFetch = () => Promise<AuthenticatedFetchCredential | null | undefined>;
/** Options for {@link toAuthenticatedFetch}. */
export interface ToAuthenticatedFetchOptions {
    /**
     * OPTIONAL silent refresh: when a request 401s (expired/invalid access token), this is
     * run ONCE to re-mint a fresh credential, which is adopted (so subsequent requests on
     * this fetch use the fresh token too) and the request is retried ONCE. Omit it for a
     * single-shot fetch that simply propagates a 401. See {@link RefreshAuthenticatedFetch}.
     */
    refresh?: RefreshAuthenticatedFetch;
    /**
     * OPTIONAL underlying fetch oauth4webapi uses to send each request. Defaults to the
     * global fetch. A test seam, and a hook for apps that wrap fetch (an SSRF-guarded fetch,
     * the reactive-auth patched global) — note the DPoP proof + Authorization header are
     * added by oauth4webapi REGARDLESS of which fetch transports the bytes.
     */
    fetch?: typeof fetch;
    /**
     * Enable oauth4webapi's `allowInsecureRequests` for `localhost` / `127.0.0.1` / `[::1]`
     * targets only (dev CSS over HTTP). Remote HTTPS targets are unaffected, and a
     * non-loopback HTTP target is never allowed. Default `false`.
     */
    allowInsecureLoopback?: boolean;
}
/**
 * Build a DPoP-AUTHENTICATED, optionally REFRESH-CAPABLE `fetch` from a
 * {@link RestoredSession}. Every request carries `Authorization: DPoP <accessToken>` and a
 * fresh per-request DPoP proof signed by the session's bound (non-extractable) key.
 *
 * The auth is attached by oauth4webapi's `protectedResourceRequest` driven by the session's
 * `dpopHandle` (built INSIDE `restoreSession` from the persisted key) and `accessToken` — we
 * never hand-roll a proof or header.
 *
 * Two DISTINCT bounded retries, in order:
 *  1. DPoP-NONCE retry (RFC 9449 §8): the server may answer the first DPoP request with a
 *     `use_dpop_nonce` challenge; the handle captures the nonce, so we retry ONCE with it
 *     primed. The nonce retry is bounded to ONCE PER returned-fetch invocation — even across
 *     the post-refresh re-send — so the contract is exactly one nonce retry per call, not one
 *     per send-attempt. This does NOT consume the token-refresh retry.
 *  2. TOKEN-REFRESH retry: the captured access token is short-lived. On a 401 (an
 *     `invalid_token` challenge OR a bare-401 response) — when a {@link
 *     ToAuthenticatedFetchOptions.refresh} is supplied — we run it ONCE to silently re-mint
 *     a fresh credential, adopt it (so subsequent requests use the fresh token too), and
 *     retry the request ONCE. If `refresh` is absent or itself fails → the 401 propagates
 *     (no loop).
 *
 * CONCURRENCY: many requests on the same returned fetch can 401 simultaneously. They share a
 * SINGLE in-flight refresh (the first 401'd request starts it; the rest await the same
 * promise), so N concurrent 401s trigger at most ONE refresh. The captured credential is only
 * ever advanced FORWARD via compare-and-set, so a refresh that resolves late cannot overwrite
 * a credential a newer refresh already installed (no stale-token reuse).
 *
 * The returned function matches the Fetch API surface (`fetch(input, init)`), adapting it to
 * `protectedResourceRequest`'s `(accessToken, method, url, headers, body, opts)` shape.
 */
export declare function toAuthenticatedFetch(session: RestoredSession, options?: ToAuthenticatedFetchOptions): typeof fetch;
//# sourceMappingURL=authenticated-fetch.d.ts.map