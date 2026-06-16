/** The remembered-account data this pointer holds — NO credential, ever. */
export interface RememberedAccountRecord {
    /** The last-active WebID (the pointer keys off this). */
    readonly webId: string;
    /** The OIDC issuer the user chose for this account (the refresh grant is per-issuer). */
    readonly issuer?: string;
}
/** The default localStorage key when an app does not supply its own. */
export declare const DEFAULT_REMEMBERED_ACCOUNT_KEY = "solid-session-restore.remembered-account";
/**
 * The credential-free, WebID→issuer pointer that selects which issuer silent
 * restore runs against on load. Backed by localStorage under an app-specific key.
 *
 * Holds NO token of any kind — only the public WebID + issuer URL the login
 * already resolved (the DPoP-bound credential lives in {@link SessionStore}).
 * Every method degrades safely when localStorage is unavailable / throwing
 * (private mode, SSR, quota) — a storage fault must never become a failed login.
 */
export declare class RememberedAccount {
    #private;
    /**
     * @param storageKey The localStorage key for this app's pointer. MUST be unique
     *   per app on a shared origin. Defaults to {@link DEFAULT_REMEMBERED_ACCOUNT_KEY};
     *   every real app SHOULD pass its own (e.g. `"pod-mail.remembered-account"`).
     */
    constructor(storageKey?: string);
    /** The localStorage key this instance reads/writes (for diagnostics / tests). */
    get key(): string;
    /** Read the pointer, or null when absent / unavailable / corrupt / no-webId. */
    read(): RememberedAccountRecord | null;
    /**
     * Remember the now-active account (WebID + its resolved issuer) so a later reload
     * can attempt a silent refresh-token restore. Overwrites any prior pointer (a new
     * identity supersedes the old one). Best-effort: a storage error degrades to
     * in-memory-only behaviour (the next load shows login), never a failed login.
     */
    write(webId: string, issuer: string): void;
    /**
     * Clear the pointer (logout / account change). Idempotent; swallows storage
     * errors. Clearing the pointer means the next load will not attempt a silent
     * restore — the credential in IndexedDB is cleared separately (forgetPersisted).
     */
    clear(): void;
}
//# sourceMappingURL=remembered-account.d.ts.map