// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Exhaustive tests for toAuthenticatedFetch — the DPoP-authenticated `fetch` derived
// from a RestoredSession. These pin the SECURITY-CRITICAL contract (every request carries
// the session's DPoP-bound access token; stale caller auth is stripped; bounded retries;
// fail-closed refresh) without a browser or network.
//
// What is pinned here (the adversarial matrix):
//   • each request goes through oauth4webapi.protectedResourceRequest with the session's
//     accessToken + its dpopHandle — proof-of-possession, never bare Bearer, never hand-rolled;
//   • the method / URL / body are forwarded from the Fetch API call (GET/HEAD carry no body;
//     a body is read once so it matches its Content-Type);
//   • a caller-supplied Authorization / DPoP header is STRIPPED before the send (a caller
//     cannot pin a foreign credential onto the authenticated request);
//   • a DPoP-nonce challenge is retried ONCE (RFC 9449 §8) and does NOT consume the refresh retry;
//   • a 401 (thrown invalid_token challenge OR returned bare-401) with a `refresh` runs the
//     refresh ONCE, adopts the fresh credential, retries ONCE, and subsequent requests use
//     the FRESH token;
//   • a 401 with NO refresh propagates the 401 (no loop);
//   • refresh that returns null/undefined / throws → the original 401 is surfaced (fail-closed);
//   • a SECOND 401 after a fresh token does NOT loop; an UNRELATED retry error rethrows (not masked);
//   • the optional `fetch` override is wired through oauth4webapi.customFetch;
//   • allowInsecureLoopback is set only for loopback hosts.
//
// oauth4webapi is mocked so the auth-attaching + retry logic is observable; the real
// library's network/crypto is out of scope here (it is exercised by restore-session.test.ts
// and the live integration in consuming apps).
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { RestoredSession } from "../src/restore-session.js";

const oauthMock = vi.hoisted(() => {
  const allowInsecureRequests = Symbol("allowInsecureRequests");
  const customFetch = Symbol("customFetch");
  return {
    allowInsecureRequests,
    customFetch,
    // Each entry: the full arg tuple protectedResourceRequest was called with.
    calls: [] as Array<{
      accessToken: string;
      method: string;
      url: URL;
      headers: Headers;
      body: unknown;
      options: Record<PropertyKey, unknown>;
    }>,
    // A queue of behaviours, one per protectedResourceRequest call. Each is either a
    // Response to resolve with, or an Error to throw.
    behaviours: [] as Array<Response | Error>,
    // Errors for which isDPoPNonceError returns true (a referential set).
    nonceErrors: new Set<unknown>(),
  };
});

vi.mock("oauth4webapi", () => ({
  allowInsecureRequests: oauthMock.allowInsecureRequests,
  customFetch: oauthMock.customFetch,
  isDPoPNonceError: (e: unknown) => oauthMock.nonceErrors.has(e),
  protectedResourceRequest: vi.fn(
    async (
      accessToken: string,
      method: string,
      url: URL,
      headers: Headers,
      body: unknown,
      options: Record<PropertyKey, unknown>,
    ): Promise<Response> => {
      oauthMock.calls.push({ accessToken, method, url, headers, body, options });
      const behaviour = oauthMock.behaviours.shift();
      if (behaviour instanceof Error) throw behaviour;
      if (behaviour instanceof Response) return behaviour;
      // Default: a 200 echoing the access token used, so a test can assert WHICH token sent.
      return new Response(`ok:${accessToken}`, { status: 200 });
    },
  ),
}));

// Import AFTER the mock is registered.
const { toAuthenticatedFetch } = await import("../src/authenticated-fetch.js");

/** A challenge-style error carrying a status (mirrors oauth4webapi WWWAuthenticateChallengeError). */
function challenge(status: number): Error {
  const e = new Error(`challenge ${status}`);
  (e as unknown as { status: number }).status = status;
  return e;
}

/** A 401 Response (a server that returns a bare 401 with no parseable challenge). */
const resp401 = () => new Response("unauthorized", { status: 401 });
const resp200 = (msg = "ok") => new Response(msg, { status: 200 });

/** A fake DPoP handle — a distinct object so identity through the call can be asserted. */
function fakeHandle(tag: string): RestoredSession["dpopHandle"] {
  return { tag } as unknown as RestoredSession["dpopHandle"];
}

/** A fake RestoredSession with the fields toAuthenticatedFetch reads (+ filler). */
function makeSession(overrides: Partial<RestoredSession> = {}): RestoredSession {
  return {
    webId: "https://alice.example/profile/card#me",
    accessToken: "access-1",
    refreshToken: "rt-1",
    dpopKey: {} as CryptoKeyPair,
    dpopHandle: fakeHandle("handle-1"),
    expiresAt: Date.now() + 60_000,
    issuer: "https://issuer.example/",
    ...overrides,
  };
}

beforeEach(() => {
  oauthMock.calls.length = 0;
  oauthMock.behaviours.length = 0;
  oauthMock.nonceErrors.clear();
});

/** The i-th protectedResourceRequest call, asserting it happened (satisfies noUncheckedIndexedAccess). */
function callAt(i: number): (typeof oauthMock.calls)[number] {
  const call = oauthMock.calls[i];
  if (call === undefined) throw new Error(`expected a protectedResourceRequest call at index ${i}`);
  return call;
}

describe("toAuthenticatedFetch — DPoP auth attachment", () => {
  it("sends the request through protectedResourceRequest with the session's token + handle", async () => {
    const session = makeSession();
    const authed = toAuthenticatedFetch(session);

    const res = await authed("https://pod.example/resource");

    expect(res.status).toBe(200);
    expect(oauthMock.calls).toHaveLength(1);
    const call = callAt(0);
    expect(call.accessToken).toBe("access-1");
    expect(call.method).toBe("GET");
    expect(call.url.href).toBe("https://pod.example/resource");
    expect(call.options.DPoP).toBe(session.dpopHandle); // DPoP-bound, the persisted-key handle
  });

  it("forwards method + body for a write, and reads the body once", async () => {
    const authed = toAuthenticatedFetch(makeSession());

    await authed("https://pod.example/doc", {
      method: "PUT",
      body: "hello world",
      headers: { "content-type": "text/plain" },
    });

    const call = callAt(0);
    expect(call.method).toBe("PUT");
    expect(call.body).toBeInstanceOf(ArrayBuffer);
    expect(new TextDecoder().decode(call.body as ArrayBuffer)).toBe("hello world");
    expect(call.headers.get("content-type")).toBe("text/plain");
  });

  it("carries no body for GET/HEAD", async () => {
    const authed = toAuthenticatedFetch(makeSession());
    await authed("https://pod.example/a");
    await authed("https://pod.example/b", { method: "HEAD" });
    expect(callAt(0).body).toBeUndefined();
    expect(callAt(1).body).toBeUndefined();
  });

  it("STRIPS a caller-supplied Authorization / DPoP header (no foreign-credential pinning)", async () => {
    const authed = toAuthenticatedFetch(makeSession());

    await authed("https://pod.example/x", {
      headers: {
        authorization: "Bearer attacker-token",
        dpop: "attacker-proof",
        "x-keep": "kept",
      },
    });

    const headers = callAt(0).headers;
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get("dpop")).toBeNull();
    expect(headers.get("x-keep")).toBe("kept"); // unrelated headers survive
  });

  it("forwards the request AbortSignal to oauth4webapi", async () => {
    const authed = toAuthenticatedFetch(makeSession());
    const controller = new AbortController();
    await authed("https://pod.example/x", { signal: controller.signal });
    expect(callAt(0).options.signal).toBeInstanceOf(AbortSignal);
  });
});

describe("toAuthenticatedFetch — DPoP-nonce retry (RFC 9449 §8)", () => {
  it("retries ONCE on a DPoP-nonce challenge and does not consume the refresh retry", async () => {
    const nonceErr = challenge(400);
    oauthMock.nonceErrors.add(nonceErr);
    oauthMock.behaviours.push(nonceErr, resp200("after-nonce"));

    const refresh = vi.fn();
    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    const res = await authed("https://pod.example/x");

    expect(await res.text()).toBe("after-nonce");
    expect(oauthMock.calls).toHaveLength(2); // first (nonce) + retry
    expect(refresh).not.toHaveBeenCalled(); // nonce is not a token-expiry
  });
});

describe("toAuthenticatedFetch — token refresh on 401", () => {
  it("refreshes on a returned bare-401, adopts the fresh token, and retries once", async () => {
    oauthMock.behaviours.push(resp401(), resp200("refreshed-ok"));
    const freshHandle = fakeHandle("handle-2");
    const refresh = vi.fn(async () => ({ accessToken: "access-2", dpopHandle: freshHandle }));

    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    const res = await authed("https://pod.example/x");

    expect(await res.text()).toBe("refreshed-ok");
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(oauthMock.calls).toHaveLength(2);
    // The retry used the FRESH token + handle.
    expect(callAt(1).accessToken).toBe("access-2");
    expect(callAt(1).options.DPoP).toBe(freshHandle);
  });

  it("refreshes on a THROWN invalid_token (401) challenge and retries once", async () => {
    oauthMock.behaviours.push(challenge(401), resp200("recovered"));
    const refresh = vi.fn(async () => ({ accessToken: "access-2", dpopHandle: fakeHandle("h2") }));

    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    const res = await authed("https://pod.example/x");

    expect(await res.text()).toBe("recovered");
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("ADOPTS the fresh credential for SUBSEQUENT requests too (in-place update)", async () => {
    // Request 1: 401 → refresh → 200. Request 2: should already use the fresh token.
    oauthMock.behaviours.push(resp401(), resp200("first"), resp200("second"));
    const refresh = vi.fn(async () => ({ accessToken: "access-2", dpopHandle: fakeHandle("h2") }));

    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    await authed("https://pod.example/1");
    await authed("https://pod.example/2");

    expect(refresh).toHaveBeenCalledTimes(1); // only refreshed once
    expect(callAt(2).accessToken).toBe("access-2"); // 2nd request used fresh token
  });

  it("propagates the 401 when NO refresh is supplied (no loop)", async () => {
    oauthMock.behaviours.push(resp401());
    const authed = toAuthenticatedFetch(makeSession());
    const res = await authed("https://pod.example/x");
    expect(res.status).toBe(401);
    expect(oauthMock.calls).toHaveLength(1); // not retried
  });
});

describe("toAuthenticatedFetch — fail-closed refresh paths", () => {
  it("surfaces the original 401 when refresh returns null", async () => {
    oauthMock.behaviours.push(resp401());
    const refresh = vi.fn(async () => null);
    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    const res = await authed("https://pod.example/x");
    expect(res.status).toBe(401);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(oauthMock.calls).toHaveLength(1); // no retry attempted
  });

  it("surfaces the original 401 when refresh returns undefined", async () => {
    oauthMock.behaviours.push(resp401());
    const refresh = vi.fn(async () => undefined);
    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    const res = await authed("https://pod.example/x");
    expect(res.status).toBe(401);
  });

  it("surfaces the original 401 when refresh itself throws (no loop)", async () => {
    oauthMock.behaviours.push(resp401());
    const refresh = vi.fn(async () => {
      throw new Error("refresh blew up");
    });
    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    const res = await authed("https://pod.example/x");
    expect(res.status).toBe(401);
  });

  it("re-throws the original thrown 401 when refresh fails (thrown-challenge path)", async () => {
    const ch = challenge(401);
    oauthMock.behaviours.push(ch);
    const refresh = vi.fn(async () => null);
    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    await expect(authed("https://pod.example/x")).rejects.toBe(ch);
  });

  it("does NOT loop on a SECOND 401 after a fresh token (returns the failure)", async () => {
    oauthMock.behaviours.push(resp401(), resp401()); // both attempts 401
    const refresh = vi.fn(async () => ({ accessToken: "access-2", dpopHandle: fakeHandle("h2") }));
    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    const res = await authed("https://pod.example/x");
    expect(res.status).toBe(401);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(oauthMock.calls).toHaveLength(2); // original + one retry, then stop
  });

  it("RETHROWS an UNRELATED retry error (not masked as the original 401)", async () => {
    const networkErr = new Error("network down");
    oauthMock.behaviours.push(resp401(), networkErr);
    const refresh = vi.fn(async () => ({ accessToken: "access-2", dpopHandle: fakeHandle("h2") }));
    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    await expect(authed("https://pod.example/x")).rejects.toBe(networkErr);
  });

  it("RETHROWS an unrelated error from the FIRST attempt (not a 401, not a nonce)", async () => {
    const err = new Error("boom 500");
    (err as unknown as { status: number }).status = 500;
    oauthMock.behaviours.push(err);
    const authed = toAuthenticatedFetch(makeSession(), { refresh: vi.fn() });
    await expect(authed("https://pod.example/x")).rejects.toBe(err);
  });
});

describe("toAuthenticatedFetch — options wiring", () => {
  it("wires the optional fetch override through oauth4webapi.customFetch", async () => {
    const appFetch = vi.fn(async () => resp200());
    const authed = toAuthenticatedFetch(makeSession(), {
      fetch: appFetch as unknown as typeof fetch,
    });
    await authed("https://pod.example/x");
    const custom = callAt(0).options[oauthMock.customFetch];
    expect(typeof custom).toBe("function");
  });

  it("does NOT set customFetch when no fetch override is given", async () => {
    const authed = toAuthenticatedFetch(makeSession());
    await authed("https://pod.example/x");
    expect(callAt(0).options[oauthMock.customFetch]).toBeUndefined();
  });

  it("sets allowInsecureRequests for a loopback host when allowInsecureLoopback is true", async () => {
    const authed = toAuthenticatedFetch(makeSession(), { allowInsecureLoopback: true });
    await authed("http://localhost:3000/x");
    expect(callAt(0).options[oauthMock.allowInsecureRequests]).toBe(true);
  });

  it("does NOT set allowInsecureRequests for a non-loopback host even when enabled", async () => {
    const authed = toAuthenticatedFetch(makeSession(), { allowInsecureLoopback: true });
    await authed("https://remote.example/x");
    expect(callAt(0).options[oauthMock.allowInsecureRequests]).toBeUndefined();
  });

  it("does NOT set allowInsecureRequests when the flag is off (default)", async () => {
    const authed = toAuthenticatedFetch(makeSession());
    await authed("http://localhost:3000/x");
    expect(callAt(0).options[oauthMock.allowInsecureRequests]).toBeUndefined();
  });
});
