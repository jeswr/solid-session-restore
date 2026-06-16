// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// remembered-account.ts — the small, durable note of WHO the returning user is so
// silent restore knows WHICH issuer's refresh-token grant to run on load.
//
// The DPoP-bound refresh token + key live in IndexedDB keyed by ISSUER
// (session-persistence.ts). To restore on a fresh load we must first know which
// issuer to ask — i.e. which account was last active and what its issuer is. This
// module holds exactly that pointer in localStorage (origin-scoped, survives a tab
// close, unlike sessionStorage). It holds NO credential — only the public WebID +
// issuer URL the login already resolved. The credential stays in IndexedDB,
// DPoP-bound.
//
// WebID-SCOPED: the record names ONE last-active WebID and its issuer. On a login
// overwrite it (a new identity replaces the old pointer); on logout / account
// change clear it, so a stale pointer can never aim silent restore at a previous
// user. The actual cross-user isolation is enforced by the per-issuer IndexedDB key
// + the WebID-match in decideSilentRestore — this is just the pointer that selects
// which issuer to try.
//
// Pure storage access (no framework), guarded against an unavailable / throwing
// localStorage (private mode, SSR) so it degrades to "no remembered account"
// (→ the login screen) rather than throwing.
//
// Extracted from the proven pod-mail pilot. The ONE deliberate generalisation: the
// localStorage KEY is injectable per app (constructor arg), so apps on a shared
// origin do not collide on the pointer; the pilot's module-level functions become
// methods on a tiny class constructed with the app's key.
/** The default localStorage key when an app does not supply its own. */
export const DEFAULT_REMEMBERED_ACCOUNT_KEY = "solid-session-restore.remembered-account";
/**
 * The credential-free, WebID→issuer pointer that selects which issuer silent
 * restore runs against on load. Backed by localStorage under an app-specific key.
 *
 * Holds NO token of any kind — only the public WebID + issuer URL the login
 * already resolved (the DPoP-bound credential lives in {@link SessionStore}).
 * Every method degrades safely when localStorage is unavailable / throwing
 * (private mode, SSR, quota) — a storage fault must never become a failed login.
 */
export class RememberedAccount {
    #key;
    /**
     * @param storageKey The localStorage key for this app's pointer. MUST be unique
     *   per app on a shared origin. Defaults to {@link DEFAULT_REMEMBERED_ACCOUNT_KEY};
     *   every real app SHOULD pass its own (e.g. `"pod-mail.remembered-account"`).
     */
    constructor(storageKey = DEFAULT_REMEMBERED_ACCOUNT_KEY) {
        this.#key = storageKey;
    }
    /** The localStorage key this instance reads/writes (for diagnostics / tests). */
    get key() {
        return this.#key;
    }
    /** Read the pointer, or null when absent / unavailable / corrupt / no-webId. */
    read() {
        let raw;
        try {
            raw = globalThis.localStorage?.getItem(this.#key) ?? null;
        }
        catch {
            return null; // localStorage unavailable (private mode / SSR) — no pointer.
        }
        if (!raw)
            return null;
        try {
            const parsed = JSON.parse(raw);
            // A record without a webId is useless (silent restore keys off the WebID).
            if (typeof parsed.webId !== "string" || parsed.webId.length === 0)
                return null;
            const hasIssuer = typeof parsed.issuer === "string" && parsed.issuer.length > 0;
            // `issuer` is optional — omit it entirely (not `: undefined`) so the record
            // satisfies `exactOptionalPropertyTypes`.
            return hasIssuer ? { webId: parsed.webId, issuer: parsed.issuer } : { webId: parsed.webId };
        }
        catch {
            return null; // corrupt JSON — treat as absent.
        }
    }
    /**
     * Remember the now-active account (WebID + its resolved issuer) so a later reload
     * can attempt a silent refresh-token restore. Overwrites any prior pointer (a new
     * identity supersedes the old one). Best-effort: a storage error degrades to
     * in-memory-only behaviour (the next load shows login), never a failed login.
     */
    write(webId, issuer) {
        try {
            globalThis.localStorage?.setItem(this.#key, JSON.stringify({ webId, issuer }));
        }
        catch {
            // localStorage unavailable / quota — silent restore just won't be available.
        }
    }
    /**
     * Clear the pointer (logout / account change). Idempotent; swallows storage
     * errors. Clearing the pointer means the next load will not attempt a silent
     * restore — the credential in IndexedDB is cleared separately (forgetPersisted).
     */
    clear() {
        try {
            globalThis.localStorage?.removeItem(this.#key);
        }
        catch {
            // Nothing to clear / unavailable.
        }
    }
}
//# sourceMappingURL=remembered-account.js.map