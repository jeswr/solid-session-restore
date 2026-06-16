import * as oauth from "oauth4webapi";
import type { SessionStore } from "./session-persistence.js";
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
export declare function isInvalidGrantError(e: unknown): boolean;
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
export declare function restoreSession(options: RestoreSessionOptions): Promise<RestoredSession | undefined>;
/**
 * Drop the durable session for an issuer (explicit logout / dead refresh token).
 * Idempotent; swallows store errors (a stale entry is harmless — its refresh token
 * is DPoP-bound, and a failed restore re-clears it).
 */
export declare function clearPersisted(store: SessionStore, issuer: URL): Promise<void>;
/** Alias for {@link clearPersisted} reading as the logout-side call. */
export declare const forgetPersisted: typeof clearPersisted;
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
export declare function hasPersisted(store: SessionStore, issuer: URL): Promise<"present" | "absent" | "unknown">;
//# sourceMappingURL=restore-session.d.ts.map