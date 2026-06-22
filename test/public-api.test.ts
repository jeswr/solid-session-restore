// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// public-api.test.ts — a dependency-free CONTRACT GUARD over the package's public
// surface, so "what is the API?" is a one-file diff for a reviewer rather than a
// code-reading exercise (the api-extractor role, without adding api-extractor as a
// dependency — keeping the audit surface lean, the whole point of this package).
//
// It snapshots, from the SINGLE public entry point (`src/index.js`):
//   • the exported RUNTIME bindings (value exports) and the runtime `typeof` of each
//     — classes, functions, constants, and the forgetPersisted/clearPersisted alias;
//   • the documented runtime VALUES of the public string constants (the DB name and
//     the localStorage key — consumers depend on these defaults);
//   • the surface of the two public CLASSES (own + prototype method names) that a
//     consumer constructs and calls.
//
// Type-only exports are not enumerable at runtime; they are pinned structurally by
// the typecheck + the behavioural suites. This guard pins the RUNTIME contract — a
// renamed/removed/added export, a changed default constant, or a changed class
// method shape all surface here as a snapshot diff a reviewer can read in seconds.
//
// A genuine, intended API change updates this snapshot in the SAME commit (with a
// semver call); an UNINTENDED change fails the gate. Never `--update` blindly.
import { describe, expect, it } from "vitest";
import * as api from "../src/index.js";

/** The runtime kind of an export, normalised for a stable, readable snapshot. */
function kindOf(value: unknown): string {
  if (typeof value === "function") {
    // A class (constructable with a prototype carrying methods) vs a plain function.
    const proto = (value as { prototype?: object }).prototype;
    const isClass = proto && Object.getOwnPropertyNames(proto).some((n) => n !== "constructor");
    return isClass ? "class" : "function";
  }
  return typeof value;
}

describe("public API — runtime surface contract (a one-file diff for review)", () => {
  it("exports exactly the documented runtime bindings, by name and kind", () => {
    const surface = Object.fromEntries(
      Object.keys(api)
        .sort()
        .map((name) => [name, kindOf((api as Record<string, unknown>)[name])]),
    );
    expect(surface).toMatchInlineSnapshot(`
      {
        "DEFAULT_DB_NAME": "string",
        "DEFAULT_REMEMBERED_ACCOUNT_KEY": "string",
        "IndexedDbSessionStore": "class",
        "RememberedAccount": "class",
        "clearPersisted": "function",
        "decideSilentRestore": "function",
        "forgetPersisted": "function",
        "hasPersisted": "function",
        "indexedDbAvailable": "function",
        "isInvalidGrantError": "function",
        "restoreSession": "function",
        "shouldDropRememberedPointer": "function",
        "toAuthenticatedFetch": "function",
        "webIdsEqual": "function",
      }
    `);
  });

  it("pins the public default constants (consumers depend on these exact values)", () => {
    expect(api.DEFAULT_DB_NAME).toBe("solid-session-restore:sessions");
    expect(api.DEFAULT_REMEMBERED_ACCOUNT_KEY).toBe("solid-session-restore.remembered-account");
  });

  it("forgetPersisted is the clearPersisted alias (the documented logout-side name)", () => {
    expect(api.forgetPersisted).toBe(api.clearPersisted);
  });

  it("pins the IndexedDbSessionStore instance surface (get/put/delete)", () => {
    const proto = api.IndexedDbSessionStore.prototype as object;
    const methods = Object.getOwnPropertyNames(proto)
      .filter((n) => n !== "constructor")
      .sort();
    expect(methods).toEqual(["delete", "get", "put"]);
  });

  it("pins the RememberedAccount instance surface (key getter + read/write/clear)", () => {
    const proto = api.RememberedAccount.prototype as object;
    const members = Object.getOwnPropertyNames(proto)
      .filter((n) => n !== "constructor")
      .sort();
    expect(members).toEqual(["clear", "key", "read", "write"]);
  });
});
