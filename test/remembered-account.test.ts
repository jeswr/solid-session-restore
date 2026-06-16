// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Tests for the remembered-account pointer (WebID + issuer in localStorage) that
// selects WHICH issuer silent restore runs against on load. Pins: round-trip
// write→read; overwrite (new identity supersedes); clear (logout/account change);
// corrupt-JSON / missing-webId → treated as absent; storage errors swallowed; the
// injectable per-app KEY (two apps on a shared origin don't collide); and the
// load-bearing security property — the pointer holds NO credential (no token).
//
// Each test installs a faithful in-memory Storage double on globalThis (Node's test
// runtime has no localStorage).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_REMEMBERED_ACCOUNT_KEY, RememberedAccount } from "../src/remembered-account.js";

const WEBID_A = "https://alice.example/profile/card#me";
const WEBID_B = "https://bob.example/profile/card#me";
const ISSUER_A = "https://issuer-a.example/";
const ISSUER_B = "https://issuer-b.example/";

/** A minimal in-memory localStorage double, optionally throwing on a chosen op. */
function installLocalStorage(throwOn?: "getItem" | "setItem" | "removeItem"): Map<string, string> {
  const store = new Map<string, string>();
  const guard = (op: "getItem" | "setItem" | "removeItem") => {
    if (throwOn === op) throw new Error(`${op} blocked`);
  };
  const stub: Pick<Storage, "getItem" | "setItem" | "removeItem"> = {
    getItem: (k) => {
      guard("getItem");
      return store.get(k) ?? null;
    },
    setItem: (k, v) => {
      guard("setItem");
      store.set(k, String(v));
    },
    removeItem: (k) => {
      guard("removeItem");
      store.delete(k);
    },
  };
  (globalThis as { localStorage?: unknown }).localStorage = stub;
  return store;
}

describe("RememberedAccount — durable WebID→issuer pointer for silent restore", () => {
  let store: Map<string, string>;
  let remembered: RememberedAccount;
  beforeEach(() => {
    store = installLocalStorage();
    remembered = new RememberedAccount("pod-mail.remembered-account");
  });
  afterEach(() => {
    delete (globalThis as { localStorage?: unknown }).localStorage;
  });

  it("round-trips a written account (WebID + issuer)", () => {
    remembered.write(WEBID_A, ISSUER_A);
    expect(remembered.read()).toEqual({ webId: WEBID_A, issuer: ISSUER_A });
  });

  it("returns null when nothing is remembered", () => {
    expect(remembered.read()).toBeNull();
  });

  it("OVERWRITES on a new identity (a re-login as B supersedes A's pointer)", () => {
    remembered.write(WEBID_A, ISSUER_A);
    remembered.write(WEBID_B, ISSUER_B);
    expect(remembered.read()).toEqual({ webId: WEBID_B, issuer: ISSUER_B });
  });

  it("clears the pointer (logout / account change)", () => {
    remembered.write(WEBID_A, ISSUER_A);
    remembered.clear();
    expect(remembered.read()).toBeNull();
  });

  it("treats corrupt JSON as absent (no throw)", () => {
    store.set(remembered.key, "{not json");
    expect(remembered.read()).toBeNull();
  });

  it("treats a record with no webId as absent (silent restore keys off the WebID)", () => {
    store.set(remembered.key, JSON.stringify({ issuer: ISSUER_A }));
    expect(remembered.read()).toBeNull();
  });

  it("reads a record with a webId but NO issuer (→ silent restore then falls through to login)", () => {
    store.set(remembered.key, JSON.stringify({ webId: WEBID_A }));
    expect(remembered.read()).toEqual({ webId: WEBID_A });
  });

  it("uses the DEFAULT key when none is supplied", () => {
    const def = new RememberedAccount();
    expect(def.key).toBe(DEFAULT_REMEMBERED_ACCOUNT_KEY);
    def.write(WEBID_A, ISSUER_A);
    expect(store.has(DEFAULT_REMEMBERED_ACCOUNT_KEY)).toBe(true);
  });

  it("ISOLATES by injectable key — two apps on a shared origin don't collide", () => {
    const mail = new RememberedAccount("pod-mail.remembered-account");
    const music = new RememberedAccount("pod-music.remembered-account");
    mail.write(WEBID_A, ISSUER_A);
    music.write(WEBID_B, ISSUER_B);
    // Each app reads only its OWN pointer.
    expect(mail.read()).toEqual({ webId: WEBID_A, issuer: ISSUER_A });
    expect(music.read()).toEqual({ webId: WEBID_B, issuer: ISSUER_B });
    // Clearing one does not touch the other.
    mail.clear();
    expect(mail.read()).toBeNull();
    expect(music.read()).toEqual({ webId: WEBID_B, issuer: ISSUER_B });
  });

  it("SECURITY: the persisted pointer holds NO credential — no token field of any kind", () => {
    remembered.write(WEBID_A, ISSUER_A);
    const raw = store.get(remembered.key) ?? "";
    expect(raw).not.toMatch(/token/i);
    expect(raw).not.toMatch(/refresh/i);
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    expect(Object.keys(parsed).sort()).toEqual(["issuer", "webId"]);
  });
});

describe("RememberedAccount — degrades safely when localStorage throws / is absent", () => {
  afterEach(() => {
    delete (globalThis as { localStorage?: unknown }).localStorage;
  });

  it("swallows a throwing setItem (quota / private mode) — never a failed login", () => {
    installLocalStorage("setItem");
    const r = new RememberedAccount("pod-mail.remembered-account");
    expect(() => r.write(WEBID_A, ISSUER_A)).not.toThrow();
  });

  it("swallows a throwing getItem — returns null", () => {
    installLocalStorage("getItem");
    const r = new RememberedAccount("pod-mail.remembered-account");
    expect(r.read()).toBeNull();
  });

  it("swallows a throwing removeItem — idempotent clear", () => {
    installLocalStorage("removeItem");
    const r = new RememberedAccount("pod-mail.remembered-account");
    expect(() => r.clear()).not.toThrow();
  });

  it("returns null + no-ops when localStorage is entirely absent (SSR)", () => {
    delete (globalThis as { localStorage?: unknown }).localStorage;
    const r = new RememberedAccount("pod-mail.remembered-account");
    expect(r.read()).toBeNull();
    expect(() => r.write(WEBID_A, ISSUER_A)).not.toThrow();
    expect(() => r.clear()).not.toThrow();
  });
});
