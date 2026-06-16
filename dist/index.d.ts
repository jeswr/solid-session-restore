export { DEFAULT_REMEMBERED_ACCOUNT_KEY, RememberedAccount, type RememberedAccountRecord, } from "./remembered-account.js";
export { clearPersisted, forgetPersisted, hasPersisted, isInvalidGrantError, type RestoredSession, type RestoreSessionOptions, restoreSession, } from "./restore-session.js";
export { DEFAULT_DB_NAME, IndexedDbSessionStore, type IndexedDbSessionStoreOptions, indexedDbAvailable, type PersistedSession, type SessionStore, } from "./session-persistence.js";
export { type CredentialPresence, decideSilentRestore, type LoginReason, type RememberedAccount as RememberedAccountDecisionShape, type RestoreIssuer, type SessionRestoreDecision, type SilentRestoreInputs, shouldDropRememberedPointer, webIdsEqual, } from "./session-restore.js";
//# sourceMappingURL=index.d.ts.map