// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// @jeswr/solid-session-restore — the framework-agnostic, app-agnostic CORE of
// silent Solid-OIDC session restore on load, extracted from the proven pod-mail
// pilot so the suite's vite pod-apps consume ONE audited implementation instead of
// N copies of security-critical auth code.
//
// The CORE is everything below. The THIN per-app wiring (the provider hook +
// the `runSilentRestore` mount effect) stays in each app — see the README.
// ── Credential-free remembered-account pointer (localStorage; key injectable) ──
export { DEFAULT_REMEMBERED_ACCOUNT_KEY, RememberedAccount, } from "./remembered-account";
// ── The DPoP-bound refresh-token-grant restore helper + lifecycle ──
export { clearPersisted, forgetPersisted, hasPersisted, isInvalidGrantError, restoreSession, } from "./restore-session";
// ── Durable, WebID/issuer-scoped credential store (IndexedDB; DB name injectable) ──
export { DEFAULT_DB_NAME, IndexedDbSessionStore, indexedDbAvailable, } from "./session-persistence";
// ── The PURE mount-time restore decision + keep/drop-pointer matrix ──
export { decideSilentRestore, shouldDropRememberedPointer, webIdsEqual, } from "./session-restore";
//# sourceMappingURL=index.js.map