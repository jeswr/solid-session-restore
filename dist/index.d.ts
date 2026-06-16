export { DEFAULT_REMEMBERED_ACCOUNT_KEY, RememberedAccount, type RememberedAccountRecord, } from "./remembered-account";
export { clearPersisted, forgetPersisted, hasPersisted, isInvalidGrantError, type RestoredSession, type RestoreSessionOptions, restoreSession, } from "./restore-session";
export { DEFAULT_DB_NAME, IndexedDbSessionStore, type IndexedDbSessionStoreOptions, indexedDbAvailable, type PersistedSession, type SessionStore, } from "./session-persistence";
export { type CredentialPresence, decideSilentRestore, type LoginReason, type RememberedAccount as RememberedAccountDecisionShape, type RestoreIssuer, type SessionRestoreDecision, type SilentRestoreInputs, shouldDropRememberedPointer, webIdsEqual, } from "./session-restore";
//# sourceMappingURL=index.d.ts.map