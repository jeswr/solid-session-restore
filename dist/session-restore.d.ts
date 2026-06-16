import type { RememberedAccountRecord } from "./remembered-account.js";
/**
 * Why a `login` decision was reached — drives whether the caller should DROP the
 * remembered-account pointer (a doomed retry) or KEEP it (a transient blip the
 * credential survived, worth retrying on the next load):
 *  - `"no-account"`     — nothing remembered (no pointer of interest).
 *  - `"no-issuer"`      — the remembered account has no usable issuer → unusable
 *                          pointer, drop it.
 *  - `"restore-failed"` — the refresh grant returned undefined OR threw. The
 *                          credential may still be valid (the implementation clears
 *                          it ONLY on a definitive invalid_grant), so the CALLER
 *                          checks whether it survived before deciding to keep/drop.
 *  - `"webid-mismatch"` — the refresh grant SUCCEEDED but authenticated a DIFFERENT
 *                          WebID than the remembered one (fail-closed). The credential
 *                          is intact but KNOWN-BAD for this pointer, so drop it (it
 *                          would fail the isolation check on every reload).
 */
export type LoginReason = "no-account" | "no-issuer" | "restore-failed" | "webid-mismatch";
/** Where the mount-time restore decision lands. */
export type SessionRestoreDecision = {
    /** A live session was restored silently — render the app, no login UI. */
    readonly outcome: "restored";
    /** The authenticated WebID (from the restored session). */
    readonly webId: string;
    /** The issuer whose refresh-token session was restored. */
    readonly issuer: string;
} | {
    /** No usable persisted session — the login screen must be shown. */
    readonly outcome: "login";
    /** Why login was reached (drives the caller's keep/drop-pointer decision). */
    readonly reason: LoginReason;
};
/** The remembered-account shape this decision needs (re-exported as the canonical record). */
export type RememberedAccount = RememberedAccountRecord;
/**
 * Attempt a silent refresh-token restore for a known issuer. Resolves to the
 * authenticated WebID on success, or `undefined` when there is nothing to
 * restore OR the persisted refresh token is dead (expired / revoked) — in which
 * case the implementation has already cleared the dead entry. MUST NOT open a
 * popup/iframe (it is a token-endpoint fetch only) and MUST NOT throw for the
 * "no/expired token" case — that is the normal `undefined` path.
 *
 * Production wires the app's token provider's restore method (e.g. a wrapper around
 * {@link restoreSession}).
 */
export type RestoreIssuer = (issuer: string) => Promise<{
    webId: string;
} | undefined>;
/** Inputs to {@link decideSilentRestore} — all injected so it is pure + testable. */
export interface SilentRestoreInputs {
    /** The last active WebID (`null`/`undefined` when the user never signed in here). */
    readonly lastActiveWebId: string | null | undefined;
    /** The remembered accounts (to map the active WebID → its chosen issuer). */
    readonly remembered: readonly RememberedAccount[];
    /** The silent refresh-grant restore (see {@link RestoreIssuer}). */
    readonly restoreIssuer: RestoreIssuer;
    /**
     * The WebID identity comparison the rest of the auth seam uses
     * ({@link webIdsEqual}). Injected (like the other pure auth deciders take it) so
     * matching the last-active WebID to its remembered account uses the EXACT equality
     * the caller uses — a trivial host/scheme-case difference between the stored
     * "active" WebID and the remembered record must not silently lose the issuer
     * mapping. Defaults to the package's {@link webIdsEqual} when omitted.
     */
    readonly webIdsEqual?: (a: string | undefined, b: string | undefined) => boolean;
}
/**
 * Decide, on a fresh page load, whether a returning user's session can be
 * restored SILENTLY (no popup/iframe, no login screen) from their persisted
 * DPoP-bound refresh token, or whether the login screen must be shown.
 *
 * Pure except for the injected {@link RestoreIssuer} (the one fetch). Never
 * throws: a thrown `restoreIssuer` (an unexpected error, not the normal
 * expired/revoked `undefined`) is treated as "could not restore" → LOGIN, which
 * is the safe, fail-closed default (we never assert a session we could not
 * actually rebuild).
 *
 * WebID-SCOPED ISOLATION (security): the issuer used for the refresh grant is the
 * one remembered FOR THE LAST-ACTIVE WEBID. Account A's last-active WebID resolves
 * to A's issuer (and A's persisted refresh token under that issuer); it can never
 * restore account B's session — B's token lives under B's issuer key, which this
 * decision never reaches for an A-active load.
 *
 * On `restored` the caller has, in-memory, a live session whose issuer is pinned
 * in the token provider, so a later private read upgrades without prompting; the
 * caller still loads the (cosmetic) profile separately and may let it degrade.
 */
export declare function decideSilentRestore(inputs: SilentRestoreInputs): Promise<SessionRestoreDecision>;
/** Whether the durable credential is still present for the remembered issuer. */
export type CredentialPresence = "present" | "absent" | "unknown";
/**
 * Decide whether to DROP the remembered-account pointer after a `login`
 * decision, given the reason and (for the restore-failed case) whether the
 * durable credential survived. PURE so the keep/drop matrix is unit-tested.
 *
 *  - `no-account`     → drop (nothing useful; idempotent).
 *  - `no-issuer`      → drop (an unusable pointer with no issuer).
 *  - `webid-mismatch` → drop (the credential is intact but KNOWN-BAD for this
 *                        pointer — it fails the isolation check every reload).
 *  - `restore-failed` → KEEP iff the credential is `present` OR `unknown` (a
 *                        transient blip may have preserved it / a store-read error
 *                        cannot prove it gone); DROP only when `absent` (a
 *                        definitive invalid_grant cleared it, or there is no store).
 *
 * Keeping a pointer over a credential that is actually gone costs at most one extra
 * doomed restore next load (which then re-clears); dropping a pointer over a
 * credential that is actually present orphans it forever — so we bias to KEEP under
 * uncertainty (`unknown`).
 */
export declare function shouldDropRememberedPointer(reason: LoginReason, credential: CredentialPresence): boolean;
/**
 * Compare two WebIDs for IDENTITY equality, tolerant only of trivial URL
 * normalisation (case-insensitive scheme + host, default-port elision), never of
 * a different path/fragment. Returns false if either side is missing or unparseable
 * — an unverifiable identity must FAIL closed, not pass. The default equality used
 * by {@link decideSilentRestore}; matches the pod-mail/pod-manager auth seam so the
 * extracted decision is bit-for-bit compatible with the apps consuming it.
 */
export declare function webIdsEqual(a: string | undefined, b: string | undefined): boolean;
//# sourceMappingURL=session-restore.d.ts.map