// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Exhaustive, security-critical tests for the PURE silent-session-restore decision
// (no browser, no oauth stack — the one fetch is injected). The branch table this
// pins: nothing remembered → login; no remembered issuer → login; refresh grant
// succeeds → restored; refresh grant returns undefined (expired/revoked) → login;
// an UNEXPECTED throw → login (fail-closed); a restored WebID that disagrees with
// the last-active WebID → login (fail-closed); and the WebID-scoped isolation
// invariant (account A's pointer can never restore B). Also pins the keep/drop
// matrix and the default-equality path (webIdsEqual injected vs defaulted).
import { describe, expect, it, vi } from "vitest";
import {
  decideSilentRestore,
  type RememberedAccount,
  shouldDropRememberedPointer,
  webIdsEqual,
} from "../src/session-restore";

const WEBID_A = "https://alice.example/profile/card#me";
const WEBID_B = "https://bob.example/profile/card#me";
const ISSUER_A = "https://issuer-a.example/";
const ISSUER_B = "https://issuer-b.example/";

describe("webIdsEqual — identity equality (fail-closed)", () => {
  it("equal for trivially-normalised forms (case-insensitive scheme/host)", () => {
    expect(webIdsEqual(WEBID_A, "https://Alice.Example/profile/card#me")).toBe(true);
  });
  it("unequal for a different path/fragment", () => {
    expect(webIdsEqual(WEBID_A, "https://alice.example/profile/card#other")).toBe(false);
    expect(webIdsEqual(WEBID_A, "https://alice.example/other#me")).toBe(false);
  });
  it("FAILS CLOSED for a missing or unparseable side", () => {
    expect(webIdsEqual(WEBID_A, undefined)).toBe(false);
    expect(webIdsEqual(undefined, WEBID_A)).toBe(false);
    expect(webIdsEqual("not a url", WEBID_A)).toBe(false);
    expect(webIdsEqual(WEBID_A, "not a url")).toBe(false);
  });
});

describe("decideSilentRestore — the mount-time restore branch table", () => {
  it("LOGIN when there is no remembered active account (nothing to restore)", async () => {
    const restoreIssuer = vi.fn(async () => ({ webId: WEBID_A }));
    const decision = await decideSilentRestore({
      lastActiveWebId: null,
      remembered: [],
      restoreIssuer,
      webIdsEqual,
    });
    expect(decision).toEqual({ outcome: "login", reason: "no-account" });
    // The refresh grant must NOT be attempted when nothing is remembered.
    expect(restoreIssuer).not.toHaveBeenCalled();
  });

  it("LOGIN when the active WebID has no remembered issuer (a refresh grant is per-issuer)", async () => {
    const restoreIssuer = vi.fn(async () => ({ webId: WEBID_A }));
    const decision = await decideSilentRestore({
      lastActiveWebId: WEBID_A,
      remembered: [{ webId: WEBID_A }], // no issuer field
      restoreIssuer,
      webIdsEqual,
    });
    expect(decision).toEqual({ outcome: "login", reason: "no-issuer" });
    expect(restoreIssuer).not.toHaveBeenCalled();
  });

  it("RESTORED when the refresh grant succeeds — session re-established with no popup", async () => {
    const restoreIssuer = vi.fn(async () => ({ webId: WEBID_A }));
    const decision = await decideSilentRestore({
      lastActiveWebId: WEBID_A,
      remembered: [{ webId: WEBID_A, issuer: ISSUER_A }],
      restoreIssuer,
      webIdsEqual,
    });
    expect(decision).toEqual({ outcome: "restored", webId: WEBID_A, issuer: ISSUER_A });
    // The refresh grant ran against the REMEMBERED issuer (per-issuer credential).
    expect(restoreIssuer).toHaveBeenCalledExactlyOnceWith(ISSUER_A);
  });

  it("uses the package default webIdsEqual when none is injected", async () => {
    // Omit webIdsEqual entirely — the decision must still match case-insensitively.
    const restoreIssuer = vi.fn(async () => ({ webId: WEBID_A }));
    const decision = await decideSilentRestore({
      lastActiveWebId: "https://Alice.Example/profile/card#me",
      remembered: [{ webId: WEBID_A, issuer: ISSUER_A }],
      restoreIssuer,
    });
    expect(decision.outcome).toBe("restored");
    expect(restoreIssuer).toHaveBeenCalledExactlyOnceWith(ISSUER_A);
  });

  it("LOGIN when the refresh grant returns undefined (expired / revoked / no token)", async () => {
    // restoreIssuer resolves undefined for the dead/absent-token case (it has
    // already cleared the dead persisted entry) — NOT throwing. → login screen.
    const restoreIssuer = vi.fn(async () => undefined);
    const decision = await decideSilentRestore({
      lastActiveWebId: WEBID_A,
      remembered: [{ webId: WEBID_A, issuer: ISSUER_A }],
      restoreIssuer,
      webIdsEqual,
    });
    expect(decision).toEqual({ outcome: "login", reason: "restore-failed" });
    expect(restoreIssuer).toHaveBeenCalledOnce();
  });

  it("LOGIN (fail-closed) when the refresh grant THROWS unexpectedly — never asserts an unrebuilt session", async () => {
    const restoreIssuer = vi.fn(async () => {
      throw new Error("token endpoint 500");
    });
    const decision = await decideSilentRestore({
      lastActiveWebId: WEBID_A,
      remembered: [{ webId: WEBID_A, issuer: ISSUER_A }],
      restoreIssuer,
      webIdsEqual,
    });
    expect(decision).toEqual({ outcome: "login", reason: "restore-failed" });
  });

  it("LOGIN (fail-closed) when the restored WebID disagrees with the last-active WebID", async () => {
    // A corrupted/misfiled store hands back a session for a DIFFERENT WebID than the
    // one we asked to restore: never silently log the user in as someone else.
    const restoreIssuer = vi.fn(async () => ({ webId: WEBID_B }));
    const decision = await decideSilentRestore({
      lastActiveWebId: WEBID_A,
      remembered: [{ webId: WEBID_A, issuer: ISSUER_A }],
      restoreIssuer,
      webIdsEqual,
    });
    expect(decision).toEqual({ outcome: "login", reason: "webid-mismatch" });
  });

  it("matches the active WebID to its remembered record case-insensitively on host/scheme (no lost issuer)", async () => {
    const restoreIssuer = vi.fn(async () => ({ webId: WEBID_A }));
    // The stored "active" WebID differs only by host-case from the remembered record.
    const decision = await decideSilentRestore({
      lastActiveWebId: "https://Alice.Example/profile/card#me",
      remembered: [{ webId: WEBID_A, issuer: ISSUER_A }],
      restoreIssuer,
      webIdsEqual,
    });
    expect(decision.outcome).toBe("restored");
    expect(restoreIssuer).toHaveBeenCalledExactlyOnceWith(ISSUER_A);
  });
});

describe("decideSilentRestore — WebID-scoped isolation (account A's pointer never restores B)", () => {
  it("uses ONLY the last-active WebID's issuer — B's remembered record is never used for an A-active load", async () => {
    // The store remembers BOTH accounts; only A is last-active. The refresh grant
    // MUST target A's issuer (A's per-issuer credential), never B's.
    const remembered: RememberedAccount[] = [
      { webId: WEBID_A, issuer: ISSUER_A },
      { webId: WEBID_B, issuer: ISSUER_B },
    ];
    const restoreIssuer = vi.fn(async (issuer: string) =>
      issuer === ISSUER_A ? { webId: WEBID_A } : { webId: WEBID_B },
    );
    const decision = await decideSilentRestore({
      lastActiveWebId: WEBID_A,
      remembered,
      restoreIssuer,
      webIdsEqual,
    });
    expect(decision).toEqual({ outcome: "restored", webId: WEBID_A, issuer: ISSUER_A });
    // B's issuer was NEVER touched — A's session cannot be restored from B's token.
    expect(restoreIssuer).toHaveBeenCalledExactlyOnceWith(ISSUER_A);
    expect(restoreIssuer).not.toHaveBeenCalledWith(ISSUER_B);
  });

  it("never cross-restores: an A-active load whose A-issuer token is dead does NOT fall back to B's token", async () => {
    const remembered: RememberedAccount[] = [
      { webId: WEBID_A, issuer: ISSUER_A },
      { webId: WEBID_B, issuer: ISSUER_B },
    ];
    // A's token is dead (undefined); B's is alive. The decision must be LOGIN — it
    // must NOT silently restore B's session for an A-active load.
    const restoreIssuer = vi.fn(async (issuer: string) =>
      issuer === ISSUER_A ? undefined : { webId: WEBID_B },
    );
    const decision = await decideSilentRestore({
      lastActiveWebId: WEBID_A,
      remembered,
      restoreIssuer,
      webIdsEqual,
    });
    expect(decision).toEqual({ outcome: "login", reason: "restore-failed" });
    expect(restoreIssuer).toHaveBeenCalledExactlyOnceWith(ISSUER_A);
    expect(restoreIssuer).not.toHaveBeenCalledWith(ISSUER_B);
  });
});

describe("shouldDropRememberedPointer — keep/drop the pointer after a login decision", () => {
  it("drops on no-account / no-issuer / webid-mismatch (regardless of credential state)", () => {
    for (const cred of ["present", "absent", "unknown"] as const) {
      expect(shouldDropRememberedPointer("no-account", cred)).toBe(true);
      expect(shouldDropRememberedPointer("no-issuer", cred)).toBe(true);
      // webid-mismatch: the credential is intact but KNOWN-BAD for this pointer.
      expect(shouldDropRememberedPointer("webid-mismatch", cred)).toBe(true);
    }
  });

  it("on restore-failed: DROP only when the credential is definitively absent", () => {
    expect(shouldDropRememberedPointer("restore-failed", "absent")).toBe(true);
    // KEEP when present (transient blip preserved it) or unknown (store read failed —
    // cannot prove it gone; dropping would orphan a possibly-valid credential).
    expect(shouldDropRememberedPointer("restore-failed", "present")).toBe(false);
    expect(shouldDropRememberedPointer("restore-failed", "unknown")).toBe(false);
  });
});
