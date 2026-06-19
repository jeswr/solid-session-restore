// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// session-persistence.ts — durable, WebID/issuer-scoped storage for a returning
// user's DPoP-bound refresh-token session, so REOPENING A CLOSED TAB restores the
// session via a refresh_token grant (a plain token-endpoint FETCH) instead of
// bouncing to the login screen. This is the suite-wide cross-app UX invariant #1
// (silent session restore on load).
//
// Extracted verbatim (modulo the injectable DB name) from the proven, roborev-clean
// pod-mail pilot, which was itself ported from solid-pod-manager's reference
// implementation. The ONE deliberate generalisation: the IndexedDB database name is
// INJECTABLE per app (constructor option), so two apps on the same origin do NOT
// share a session store — account isolation is per-app AND per-issuer.
//
// ─── Why this is the modern best practice ────────────────────────────────────
// OAuth 2.0 for Browser-Based Apps (BCP) recommends refresh-token rotation for
// SPAs over the legacy hidden-iframe silent-renew. We persist the rotated,
// DPoP-sender-constrained refresh token and the DPoP key that constrains it, and
// restore with a `refresh_token` grant. No window, no iframe.
//
// ─── Threat model (this module persists a credential — read before changing) ──
// What we persist per issuer: the refresh token (string) + the DPoP CryptoKeyPair
// + WebID + issuer (+ optional clientId / expiresAt / a CONFIDENTIAL-CLIENT secret).
// We DO NOT persist the access token (it is short-lived and re-minted by the refresh
// grant on restore).
//
//   • Confidential-client secret (OPTIONAL — bespoke, ESS/PodSpaces path). A handful
//     of Solid-OIDC servers (notably Inrupt ESS / PodSpaces) hand back a
//     `client_secret` + `token_endpoint_auth_method: "client_secret_basic"` from
//     DYNAMIC client registration. For such a session the refresh-token grant must
//     present that secret (RFC 6749 §2.3 / OIDC Core §9) or it fails client
//     authentication — so to restore a closed tab we must persist it. It is held in
//     the SAME origin-scoped, app-scoped IndexedDB store as the refresh token, under
//     the same fail-closed / clear-on-logout discipline, and is NEVER logged. Storing
//     it is strictly NO WORSE than storing the refresh token it authorises (an
//     on-origin XSS that can read one can read both); off-origin it is useless
//     because the grant is ALSO DPoP-bound to the non-extractable key. A PUBLIC
//     client (static Client Identifier Document / PKCE) persists NO secret — the
//     field is simply absent, and the grant uses `none` auth as before.
//
//   • The DPoP private key is stored in IndexedDB as a `CryptoKey` with
//     `extractable: false`. IndexedDB can structured-clone a non-extractable
//     CryptoKey: the raw private-key BYTES never enter JS and never hit disk in a
//     readable form — only an opaque handle the browser can sign with. This is
//     the property that makes persisting the refresh token acceptable. (Callers
//     MUST generate the persisted key with `extractable: false` — the bundled
//     {@link restoreSession} helper and the documented login wiring both do.)
//
//   • The refresh token IS readable by any script on this origin (it is a plain
//     string in IndexedDB). An XSS that can run on the origin could read it.
//     BUT the token is DPoP sender-constrained (RFC 9449): redeeming it at the
//     token endpoint requires a DPoP proof signed by the matching private key,
//     and that key is non-extractable. A stolen refresh token is therefore
//     useless off-origin — the attacker cannot mint the proof. This matches the
//     DPoP refresh-token security model: sender-constraining downgrades a
//     bearer-credential exfiltration to an on-origin-only capability. (Same-origin
//     XSS that can also sign with the key is a strictly worse compromise than
//     refresh-token theft and is out of scope for token-storage hardening; the
//     mitigations there are CSP / dependency hygiene, not storage choice.)
//
//   • IndexedDB is origin-scoped: another origin cannot read this store
//     (cross-origin isolation is enforced by the browser, not by us).
//
//   • The refresh token is NEVER logged. Clear the persisted entry on explicit
//     logout, on a WebID/account change, and whenever the token endpoint answers
//     `invalid_grant` (expired / revoked / rotation-reuse), so a dead token does
//     not linger.
//
// The store is an injectable interface so unit tests can supply an in-memory
// double; production wires {@link IndexedDbSessionStore}.
/** The default IndexedDB database name when an app does not supply its own. */
export const DEFAULT_DB_NAME = "solid-session-restore:sessions";
const DB_VERSION = 1;
const STORE_NAME = "sessions";
/**
 * IndexedDB-backed {@link SessionStore}. One object store keyed by `issuer`,
 * holding the whole {@link PersistedSession} including the CryptoKeyPair (stored
 * directly — IndexedDB structured-clones non-extractable CryptoKeys).
 *
 * Origin-scoped by the platform AND app-scoped by {@link IndexedDbSessionStoreOptions.dbName}.
 * Construct only in the browser; guard with {@link indexedDbAvailable} before use.
 */
export class IndexedDbSessionStore {
    #factory;
    #dbName;
    constructor(options = {}) {
        this.#factory = options.factory ?? globalThis.indexedDB;
        this.#dbName = options.dbName ?? DEFAULT_DB_NAME;
    }
    #open() {
        return new Promise((resolve, reject) => {
            const request = this.#factory.open(this.#dbName, DB_VERSION);
            request.onupgradeneeded = () => {
                const db = request.result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    db.createObjectStore(STORE_NAME, { keyPath: "issuer" });
                }
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }
    /**
     * Run one request inside a transaction and resolve when it is DURABLE.
     *
     * Writes (put/delete) resolve from `tx.oncomplete` — the transaction has
     * COMMITTED — so the caller never treats a credential as persisted/deleted
     * before it actually hit disk (resolving on `request.success` alone races the
     * commit). Reads (get) resolve from `request.onsuccess` with the read value (a
     * read has no durable mutation to await — its result IS the value, and the
     * readonly transaction completing carries no extra meaning). Either way a
     * `tx.onabort`/`tx.onerror` rejects, and the connection is closed in `finally`.
     */
    async #tx(mode, run) {
        const db = await this.#open();
        try {
            return await new Promise((resolve, reject) => {
                const tx = db.transaction(STORE_NAME, mode);
                const request = run(tx.objectStore(STORE_NAME));
                if (mode === "readonly") {
                    // A read: its result is available on success; no commit to await.
                    request.onsuccess = () => resolve(request.result);
                }
                else {
                    // A write: capture the request result, but only resolve once the
                    // transaction has COMMITTED (oncomplete) so persistence is durable.
                    let result;
                    request.onsuccess = () => {
                        result = request.result;
                    };
                    tx.oncomplete = () => resolve(result);
                }
                request.onerror = () => reject(request.error);
                tx.onerror = () => reject(tx.error);
                tx.onabort = () => reject(tx.error);
            });
        }
        finally {
            db.close();
        }
    }
    async get(issuer) {
        const result = await this.#tx("readonly", (store) => store.get(issuer));
        return result ?? undefined;
    }
    async put(session) {
        await this.#tx("readwrite", (store) => store.put(session));
    }
    async delete(issuer) {
        await this.#tx("readwrite", (store) => store.delete(issuer));
    }
}
/** Whether a usable IndexedDB exists (browser, non-SSR, not a locked-down env). */
export function indexedDbAvailable() {
    return typeof globalThis.indexedDB !== "undefined";
}
//# sourceMappingURL=session-persistence.js.map