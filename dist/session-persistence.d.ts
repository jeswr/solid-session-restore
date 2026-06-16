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
export declare const DEFAULT_DB_NAME = "solid-session-restore:sessions";
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
export declare class IndexedDbSessionStore implements SessionStore {
    #private;
    constructor(options?: IndexedDbSessionStoreOptions);
    get(issuer: string): Promise<PersistedSession | undefined>;
    put(session: PersistedSession): Promise<void>;
    delete(issuer: string): Promise<void>;
}
/** Whether a usable IndexedDB exists (browser, non-SSR, not a locked-down env). */
export declare function indexedDbAvailable(): boolean;
//# sourceMappingURL=session-persistence.d.ts.map