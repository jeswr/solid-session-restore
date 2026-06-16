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
export {
  DEFAULT_REMEMBERED_ACCOUNT_KEY,
  RememberedAccount,
  type RememberedAccountRecord,
} from "./remembered-account.js";
// ── The DPoP-bound refresh-token-grant restore helper + lifecycle ──
export {
  clearPersisted,
  forgetPersisted,
  hasPersisted,
  isInvalidGrantError,
  type RestoredSession,
  type RestoreSessionOptions,
  restoreSession,
} from "./restore-session.js";
// ── Durable, WebID/issuer-scoped credential store (IndexedDB; DB name injectable) ──
export {
  DEFAULT_DB_NAME,
  IndexedDbSessionStore,
  type IndexedDbSessionStoreOptions,
  indexedDbAvailable,
  type PersistedSession,
  type SessionStore,
} from "./session-persistence.js";
// ── The PURE mount-time restore decision + keep/drop-pointer matrix ──
export {
  type CredentialPresence,
  decideSilentRestore,
  type LoginReason,
  type RememberedAccount as RememberedAccountDecisionShape,
  type RestoreIssuer,
  type SessionRestoreDecision,
  type SilentRestoreInputs,
  shouldDropRememberedPointer,
  webIdsEqual,
} from "./session-restore.js";
