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

import * as oauth from "oauth4webapi";
import type { PersistedSession, SessionStore } from "./session-persistence.js";

/** Refresh this much before the reported expiry to absorb clock skew. */
const EXPIRY_SKEW_MS = 30_000;

const isLoopback = (host: string): boolean =>
  host === "localhost" || host === "127.0.0.1" || host === "[::1]";

/** Epoch ms the access token should be treated as expired, or undefined when none reported. */
function expiresAtFrom(token: oauth.TokenEndpointResponse): number | undefined {
  return token.expires_in === undefined
    ? undefined
    : Date.now() + token.expires_in * 1000 - EXPIRY_SKEW_MS;
}

/**
 * The WebID an id_token authenticated AS. Solid-OIDC carries the WebID in the
 * `webid` claim; when absent (some servers put it in `sub`), `sub` is the WebID.
 * Returns undefined when neither is a usable string.
 */
function webIdFromClaims(claims: oauth.IDToken | undefined): string | undefined {
  if (!claims) return undefined;
  const webid = (claims as { webid?: unknown }).webid;
  if (typeof webid === "string" && webid.length > 0) return webid;
  if (typeof claims.sub === "string" && claims.sub.length > 0) return claims.sub;
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
export function isInvalidGrantError(e: unknown): boolean {
  if (e && typeof e === "object") {
    const err = e as { error?: unknown; cause?: { parameters?: URLSearchParams } };
    if (err.error === "invalid_grant") return true;
    try {
      if (err.cause?.parameters?.get("error") === "invalid_grant") return true;
    } catch {
      // .cause.parameters not a URLSearchParams — not the shape we handle.
    }
  }
  return false;
}

/** A rebuilt, live session — the credential a successful restore yields. */
export interface RestoredSession {
  /** The WebID the restored session authenticated AS. */
  webId: string;
  /** The freshly minted access token (DPoP-bound; attach as `Authorization: DPoP …`). */
  accessToken: string;
  /** The current (possibly rotated) refresh token, already re-persisted to the store. */
  refreshToken: string;
  /** The DPoP key pair (non-extractable) the access token is bound to. */
  dpopKey: CryptoKeyPair;
  /** The oauth4webapi DPoP handle bound to {@link dpopKey} (reuse for token-endpoint calls). */
  dpopHandle: oauth.DPoPHandle;
  /** Epoch ms the access token expires (server `expires_in` minus skew), or undefined. */
  expiresAt: number | undefined;
  /** The issuer this session belongs to. */
  issuer: string;
}

/** Options for {@link restoreSession}. */
export interface RestoreSessionOptions {
  /** The durable, WebID/issuer-scoped credential store. */
  store: SessionStore;
  /** The issuer to restore (the one remembered for the last-active WebID). */
  issuer: URL;
  /**
   * A **Solid-OIDC Client Identifier Document** URL. When set, the helper
   * authenticates as a public client whose `client_id` IS this URL (token-endpoint
   * auth `none`). When ABSENT, dynamic client registration is used (dev fallback).
   * MUST match the `clientId` the original login used (the refresh grant re-derives
   * the client the same way the login did).
   */
  clientId?: string;
  /**
   * The redirect_uri this client registered with — only used for the dynamic-client
   * fallback (when {@link clientId} is absent). Ignored for the static-client path.
   */
  callbackUri?: string;
  /**
   * Enable oauth4webapi's `allowInsecureRequests` for `localhost` / `127.0.0.1`
   * issuers only (dev CSS over HTTP). Remote HTTPS issuers are unaffected, and
   * non-loopback HTTP issuers are never allowed. Default `false`.
   */
  allowInsecureLoopback?: boolean;
  /** Abort signal for the discovery + grant fetches (e.g. the provider's auth controller). */
  signal?: AbortSignal;
  /**
   * The fetch used for discovery + the grant. Defaults to the global fetch. A test
   * seam and a hook for apps that wrap fetch (the patched ReactiveFetchManager).
   */
  fetch?: typeof fetch;
}

/**
 * The shared HTTP-options shape passed to every oauth4webapi call (discovery,
 * registration, the refresh grant). oauth4webapi's `customFetch` value has its own
 * call signature `(url, options)` distinct from the DOM `fetch`; we adapt the app's
 * `fetch` to it with a thin wrapper (oauth4webapi calls it with a URL string +
 * init-like options that a standard `fetch` accepts at runtime), so no unsafe cast
 * is needed and the runtime contract is explicit.
 */
type OauthCustomFetch = (
  url: string,
  options: oauth.CustomFetchOptions<string, unknown>,
) => Promise<Response>;

type OauthHttpOptions = {
  signal?: AbortSignal;
  [oauth.customFetch]?: OauthCustomFetch;
  [oauth.allowInsecureRequests]?: true;
};

/** Build the oauth4webapi HTTP options (signal + loopback-only insecure allowance). */
function httpOptions(issuer: URL, options: RestoreSessionOptions): OauthHttpOptions {
  const out: OauthHttpOptions = {};
  if (options.signal) out.signal = options.signal;
  if (options.fetch) {
    const appFetch = options.fetch;
    // oauth4webapi invokes customFetch with `(url, options)` where `options` is a
    // superset of RequestInit it constructed — pass it straight to the app's fetch
    // (runtime-compatible). The DOM `fetch` accepts `RequestInit`.
    out[oauth.customFetch] = (url, opts) => appFetch(url, opts as RequestInit);
  }
  if (options.allowInsecureLoopback && isLoopback(issuer.hostname)) {
    out[oauth.allowInsecureRequests] = true;
  }
  return out;
}

/** Discover the authorization server metadata for an issuer. */
async function discover(
  issuer: URL,
  http: ReturnType<typeof httpOptions>,
): Promise<oauth.AuthorizationServer> {
  const discoveryResponse = await oauth.discoveryRequest(issuer, http);
  return oauth.processDiscoveryResponse(issuer, discoveryResponse);
}

/**
 * Resolve the OAuth client a refresh grant must run as. A refresh token is
 * CLIENT-BOUND (RFC 6749 §6 / §10.4): it can only be redeemed by the same client
 * that obtained it. So we reuse the original client identity — `options.clientId`
 * (the app's static Client Identifier Document URL, if it used one) OR the
 * `clientId` the original login PERSISTED into the session record (which, for the
 * dynamic-registration path, is the server-assigned `client_id`). We perform a
 * FRESH dynamic registration ONLY when neither is available — a brand-new client
 * has no claim to a previously-issued refresh token, so reusing the stored id is
 * what keeps a dynamic-login user restorable instead of failing `invalid_client`
 * (roborev finding). All paths are public browser clients (`none` token-endpoint
 * auth); the persisted refresh token's DPoP-binding (not the client secret) is what
 * authorises the grant.
 */
async function resolveClient(
  authorizationServer: oauth.AuthorizationServer,
  options: RestoreSessionOptions,
  stored: PersistedSession,
  http: ReturnType<typeof httpOptions>,
): Promise<oauth.Client> {
  const clientId = options.clientId ?? stored.clientId;
  if (clientId !== undefined && clientId !== "") {
    return {
      client_id: clientId,
      token_endpoint_auth_method: "none",
      ...(options.callbackUri ? { redirect_uris: [options.callbackUri] } : {}),
      response_types: ["code"],
    };
  }
  // No persisted/static client id — fall back to a fresh dynamic registration. This
  // only succeeds against servers whose refresh tokens are not strictly bound to the
  // original registration; it is the best available behaviour for the rare case of a
  // dynamic login that never persisted its client id.
  const registrationResponse = await oauth.dynamicClientRegistrationRequest(
    authorizationServer,
    options.callbackUri ? { redirect_uris: [options.callbackUri] } : {},
    http,
  );
  return oauth.processDynamicClientRegistrationResponse(registrationResponse);
}

/**
 * The refresh-token grant (RFC 6749 §6), DPoP-bound with the supplied key/handle,
 * adopting the rotated refresh token when the server issues one. One retry on a
 * server-required DPoP nonce (the handle captures it from the error).
 */
async function refreshGrant(
  authorizationServer: oauth.AuthorizationServer,
  clientRegistration: oauth.Client,
  dpopHandle: oauth.DPoPHandle,
  refreshToken: string,
  http: ReturnType<typeof httpOptions>,
): Promise<oauth.TokenEndpointResponse> {
  // Public browser client → `none` client auth (no secret); the static-client and
  // dynamic-registration paths both register as `none` here.
  const clientAuth = oauth.None();

  const grant = () =>
    oauth.refreshTokenGrantRequest(
      authorizationServer,
      clientRegistration,
      clientAuth,
      refreshToken,
      { DPoP: dpopHandle, ...http },
    );

  try {
    return await oauth.processRefreshTokenResponse(
      authorizationServer,
      clientRegistration,
      await grant(),
    );
  } catch (e) {
    if (!oauth.isDPoPNonceError(e)) throw e;
    // The handle captured the server's DPoP nonce from the error; retry once.
    return await oauth.processRefreshTokenResponse(
      authorizationServer,
      clientRegistration,
      await grant(),
    );
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
export async function restoreSession(
  options: RestoreSessionOptions,
): Promise<RestoredSession | undefined> {
  const { store, issuer } = options;

  let stored: PersistedSession | undefined;
  try {
    stored = await store.get(issuer.href);
  } catch {
    return undefined; // store unreadable — nothing to restore, stay silent.
  }
  if (stored === undefined || stored.refreshToken === undefined || stored.refreshToken === "") {
    return undefined;
  }

  try {
    const http = httpOptions(issuer, options);
    const authorizationServer = await discover(issuer, http);
    const clientRegistration = await resolveClient(authorizationServer, options, stored, http);

    // Reattach the PERSISTED, non-extractable DPoP key — the refresh-grant proof
    // must be signed by the key the token is bound to (RFC 9449 §4.3).
    const dpopHandle = oauth.DPoP(clientRegistration, stored.dpopKey);

    const tokenResult = await refreshGrant(
      authorizationServer,
      clientRegistration,
      dpopHandle,
      stored.refreshToken,
      http,
    );

    // Adopt the rotated refresh token when the server issues one; keep the old one
    // otherwise (some servers do not rotate).
    const refreshToken = tokenResult.refresh_token ?? stored.refreshToken;
    // Prefer the id_token's WebID when the refresh response carries one; else keep
    // the WebID the persisted session authenticated AS originally.
    const webId = webIdFromClaims(oauth.getValidatedIdTokenClaims(tokenResult)) ?? stored.webId;

    const restored: RestoredSession = {
      webId,
      accessToken: tokenResult.access_token,
      refreshToken,
      dpopKey: stored.dpopKey,
      dpopHandle,
      expiresAt: expiresAtFrom(tokenResult),
      issuer: issuer.href,
    };

    // Persist the ROTATED token (servers rotate refresh tokens, RFC 9700 §4.14.2)
    // so the NEXT reload restores from the current credential, not a spent one.
    // Best-effort: a store write error must not fail an otherwise-good restore.
    try {
      await store.put({
        issuer: issuer.href,
        webId,
        refreshToken,
        dpopKey: stored.dpopKey,
        ...(stored.clientId !== undefined ? { clientId: stored.clientId } : {}),
        ...(restored.expiresAt !== undefined ? { expiresAt: restored.expiresAt } : {}),
      });
    } catch {
      // Durable re-persistence failed — the in-memory restored session is still
      // valid for THIS load; the next reload may re-prompt. Never logged.
    }

    return restored;
  } catch (e) {
    // Distinguish a DEFINITIVELY DEAD refresh token from a TRANSIENT failure: only
    // `invalid_grant` means the credential is gone — clear it so a doomed restore
    // is not re-attempted. A transient discovery/network/server error on page load
    // must NOT erase an otherwise-valid refresh token. Either way report "nothing
    // restored" so the caller falls back to login silently (no popup on restore).
    if (isInvalidGrantError(e)) await clearPersisted(store, issuer);
    return undefined;
  }
}

/**
 * Drop the durable session for an issuer (explicit logout / dead refresh token).
 * Idempotent; swallows store errors (a stale entry is harmless — its refresh token
 * is DPoP-bound, and a failed restore re-clears it).
 */
export async function clearPersisted(store: SessionStore, issuer: URL): Promise<void> {
  try {
    await store.delete(issuer.href);
  } catch {
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
export async function hasPersisted(
  store: SessionStore,
  issuer: URL,
): Promise<"present" | "absent" | "unknown"> {
  try {
    return (await store.get(issuer.href)) !== undefined ? "present" : "absent";
  } catch {
    return "unknown";
  }
}
