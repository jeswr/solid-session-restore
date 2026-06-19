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

/**
 * The OAuth token-endpoint client-authentication method a persisted session must
 * use on its refresh-token grant (RFC 6749 §2.3 / OIDC Core §9). Only the methods
 * this package supports are listed:
 *  - `"none"` — PUBLIC client (the default; PKCE/DPoP, no secret). Static Client
 *    Identifier Documents and PKCE dynamic clients are all `none` here.
 *  - `"client_secret_basic"` — CONFIDENTIAL client; the secret rides in an HTTP
 *    `Basic` Authorization header. The ESS/PodSpaces dynamic-registration path.
 *  - `"client_secret_post"` — CONFIDENTIAL client; the secret rides in the form body.
 */
export type TokenEndpointAuthMethod = "none" | "client_secret_basic" | "client_secret_post";

/**
 * One persisted session, keyed by issuer. The access token is deliberately
 * ABSENT — only the long-lived, key-bound refresh credential is durable.
 */
export interface PersistedSession {
  /** The OIDC issuer this session belongs to (the store key). */
  issuer: string;
  /** The authenticated WebID (ID-token `webid`/`sub`), for instant UI restore. */
  webId: string;
  /**
   * The DPoP-bound refresh token (RFC 6749 §6, RFC 9449). Readable on-origin but
   * unusable without {@link dpopKey} — see the module threat model.
   */
  refreshToken: string;
  /**
   * The DPoP key pair that sender-constrains {@link refreshToken}. Persisted as a
   * structured-cloneable CryptoKeyPair whose private key is `extractable: false`,
   * so the raw bytes never leave the browser's key store.
   */
  dpopKey: CryptoKeyPair;
  /** The Client Identifier Document URL used, when the session was static-client. */
  clientId?: string;
  /**
   * The token-endpoint client-authentication method this session's refresh grant
   * MUST use (RFC 6749 §2.3 / OIDC Core §9). Absent (or `"none"`) for the common
   * PUBLIC-client case — the grant then uses `none` auth. Set to
   * `"client_secret_basic"` / `"client_secret_post"` only for a CONFIDENTIAL client
   * that registered with a secret (the ESS/PodSpaces dynamic path); {@link clientSecret}
   * must then also be present. See the module threat model.
   */
  tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
  /**
   * The CONFIDENTIAL client's secret (RFC 6749 §2.3.1). Present ONLY for a
   * `client_secret_basic` / `client_secret_post` session (the rare ESS/PodSpaces
   * dynamic-registration path); ABSENT for the common public-client case. Stored in
   * the same origin/app-scoped IndexedDB as the refresh token, under the same
   * fail-closed / clear-on-logout discipline, and NEVER logged — see the module
   * threat model (it is no worse than persisting the refresh token it authorises,
   * and the grant is also DPoP-bound).
   */
  clientSecret?: string;
  /** Epoch ms the (now-discarded) access token would have expired — advisory. */
  expiresAt?: number;
}

/** The persistence contract the restore helper depends on (injectable for tests). */
export interface SessionStore {
  get(issuer: string): Promise<PersistedSession | undefined>;
  put(session: PersistedSession): Promise<void>;
  delete(issuer: string): Promise<void>;
}

/** The default IndexedDB database name when an app does not supply its own. */
export const DEFAULT_DB_NAME = "solid-session-restore:sessions";

const DB_VERSION = 1;
const STORE_NAME = "sessions";

/** Options for {@link IndexedDbSessionStore}. */
export interface IndexedDbSessionStoreOptions {
  /**
   * The IndexedDB database name. MUST be unique per app on a shared origin so two
   * apps do NOT share a session store (account isolation is per-app AND
   * per-issuer). Defaults to {@link DEFAULT_DB_NAME}; every real app SHOULD pass
   * its own (e.g. `"pod-mail:sessions"`).
   */
  dbName?: string;
  /** The IDBFactory to use. Defaults to `globalThis.indexedDB`. Test seam. */
  factory?: IDBFactory;
}

/**
 * IndexedDB-backed {@link SessionStore}. One object store keyed by `issuer`,
 * holding the whole {@link PersistedSession} including the CryptoKeyPair (stored
 * directly — IndexedDB structured-clones non-extractable CryptoKeys).
 *
 * Origin-scoped by the platform AND app-scoped by {@link IndexedDbSessionStoreOptions.dbName}.
 * Construct only in the browser; guard with {@link indexedDbAvailable} before use.
 */
export class IndexedDbSessionStore implements SessionStore {
  readonly #factory: IDBFactory;
  readonly #dbName: string;

  constructor(options: IndexedDbSessionStoreOptions = {}) {
    this.#factory = options.factory ?? globalThis.indexedDB;
    this.#dbName = options.dbName ?? DEFAULT_DB_NAME;
  }

  #open(): Promise<IDBDatabase> {
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
  async #tx<T>(
    mode: IDBTransactionMode,
    run: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> {
    const db = await this.#open();
    try {
      return await new Promise<T>((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, mode);
        const request = run(tx.objectStore(STORE_NAME));
        if (mode === "readonly") {
          // A read: its result is available on success; no commit to await.
          request.onsuccess = () => resolve(request.result);
        } else {
          // A write: capture the request result, but only resolve once the
          // transaction has COMMITTED (oncomplete) so persistence is durable.
          let result: T;
          request.onsuccess = () => {
            result = request.result;
          };
          tx.oncomplete = () => resolve(result);
        }
        request.onerror = () => reject(request.error);
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  }

  async get(issuer: string): Promise<PersistedSession | undefined> {
    const result = await this.#tx<PersistedSession | undefined>(
      "readonly",
      (store) => store.get(issuer) as IDBRequest<PersistedSession | undefined>,
    );
    return result ?? undefined;
  }

  async put(session: PersistedSession): Promise<void> {
    await this.#tx("readwrite", (store) => store.put(session));
  }

  async delete(issuer: string): Promise<void> {
    await this.#tx("readwrite", (store) => store.delete(issuer));
  }
}

/** Whether a usable IndexedDB exists (browser, non-SSR, not a locked-down env). */
export function indexedDbAvailable(): boolean {
  return typeof globalThis.indexedDB !== "undefined";
}
