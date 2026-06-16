// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// session-restore.ts — the PURE, testable decision at the heart of "reopening a
// closed tab restores the session instead of bouncing to the login screen".
//
// Extracted verbatim from the proven, roborev-clean pod-mail pilot (itself ported
// from solid-pod-manager's reference). A browser SPA holds tokens in MEMORY ONLY,
// so a fresh page load has NO live session — but a returning user who merely closed
// the tab (did NOT log out) still has their DPoP-bound refresh token +
// non-extractable key persisted in IndexedDB (see {@link ./session-persistence.ts}).
// On mount the app must try a SILENT restore from that credential — a
// `refresh_token` grant, which is a plain token-endpoint FETCH, never a popup/iframe
// — BEFORE it ever decides "logged out" and shows the login screen.
//
// This module isolates the *decision* (a pure async function over injected
// collaborators) from the framework wiring, so the security-sensitive branch table
// is unit-testable without a browser (the one fetch is injected):
//
//   • no remembered active account            → LOGIN (nothing to restore)
//   • active account, but no remembered issuer → LOGIN (a refresh grant is
//     per-issuer; without the issuer there is nothing to attempt silently)
//   • active account, refresh grant succeeds   → RESTORED (logged in, no popup)
//   • active account, refresh grant fails       → LOGIN (token expired/revoked)
//     (expired/revoked is reported by the restore as `undefined`; it has already
//      cleared the dead persisted entry — see restoreSession / the provider wiring)
//
// The decision is driven off the REFRESH-GRANT outcome, NOT off a public-profile
// fetch: a returning user with a valid restored token is logged in even if the
// (cosmetic) profile read later fails — the profile is loaded separately and is
// allowed to degrade. This is the cross-app invariant: reopening must not bounce
// a fully-restored user to the login screen on a transient profile blip.
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
export async function decideSilentRestore(inputs) {
    const { lastActiveWebId, remembered, restoreIssuer } = inputs;
    const equal = inputs.webIdsEqual ?? webIdsEqual;
    // No prior active account on this device → nothing to restore; show login.
    if (!lastActiveWebId)
        return { outcome: "login", reason: "no-account" };
    // The issuer the user chose for this account, remembered at login. Without it
    // we cannot run a refresh-token grant (the grant is per-issuer), so there is
    // no silent restore to attempt — fall through to LOGIN (an explicit click there
    // re-pins the issuer). Match the active WebID to its remembered record with the
    // SAME equality the rest of the seam uses, so a trivial case/normalisation
    // difference does not silently lose the issuer.
    const issuer = remembered.find((a) => equal(a.webId, lastActiveWebId))?.issuer;
    if (!issuer)
        return { outcome: "login", reason: "no-issuer" };
    let restored;
    try {
        restored = await restoreIssuer(issuer);
    }
    catch {
        // An UNEXPECTED restore error (not the normal expired/revoked `undefined`):
        // fail closed to LOGIN. We never claim a session we could not rebuild. The
        // credential may still be valid (a transient blip), so reason is restore-failed
        // — the caller checks whether it survived before deciding keep/drop.
        return { outcome: "login", reason: "restore-failed" };
    }
    // Expired / revoked / no persisted token: restoreIssuer returns undefined (it has
    // cleared the entry ONLY on a definitive invalid_grant; a transient failure
    // preserves it) → show login. reason restore-failed; the caller checks survival.
    if (restored === undefined)
        return { outcome: "login", reason: "restore-failed" };
    // SECURITY — confirm the restored session authenticated AS the last-active
    // WebID. The refresh grant mints a token for whatever the persisted record's
    // WebID is; if (through a corrupted/misfiled store) that disagrees with the
    // last-active WebID we asked to restore, FAIL CLOSED to login rather than
    // silently logging the user in as someone else. webIdsEqual fails closed for a
    // missing/unparseable side. reason webid-mismatch: the credential is intact but
    // KNOWN-BAD for this pointer, so the caller drops the pointer (it would fail this
    // same isolation check on every reload).
    if (!equal(restored.webId, lastActiveWebId)) {
        return { outcome: "login", reason: "webid-mismatch" };
    }
    // Live session rebuilt silently (refresh grant only): render the app.
    return { outcome: "restored", webId: restored.webId, issuer };
}
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
export function shouldDropRememberedPointer(reason, credential) {
    switch (reason) {
        case "no-account":
        case "no-issuer":
        case "webid-mismatch":
            return true;
        case "restore-failed":
            return credential === "absent";
    }
}
/**
 * Compare two WebIDs for IDENTITY equality, tolerant only of trivial URL
 * normalisation (case-insensitive scheme + host, default-port elision), never of
 * a different path/fragment. Returns false if either side is missing or unparseable
 * — an unverifiable identity must FAIL closed, not pass. The default equality used
 * by {@link decideSilentRestore}; matches the pod-mail/pod-manager auth seam so the
 * extracted decision is bit-for-bit compatible with the apps consuming it.
 */
export function webIdsEqual(a, b) {
    if (!a || !b)
        return false;
    try {
        const ua = new URL(a);
        const ub = new URL(b);
        return (ua.protocol === ub.protocol &&
            ua.host.toLowerCase() === ub.host.toLowerCase() &&
            ua.pathname === ub.pathname &&
            ua.search === ub.search &&
            ua.hash === ub.hash);
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=session-restore.js.map