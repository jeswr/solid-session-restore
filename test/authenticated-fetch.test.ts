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
    // OPTIONAL responder: when set, it (not the FIFO `behaviours` queue) decides each call's
    // outcome by INSPECTING the (accessToken, url) — so a concurrency test stays deterministic
    // regardless of microtask interleaving (no reliance on strict call ORDER). It returns (or
    // resolves to) a Response to resolve with, or an Error to throw; an async responder can PARK
    // a send (e.g. on a gate) to deterministically order failure-handling. When null, the FIFO
    // queue is used.
    responder: null as
      | null
      | ((accessToken: string, url: URL) => Response | Error | Promise<Response | Error>),
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
      // An order-independent responder takes precedence over the FIFO queue when present.
      if (oauthMock.responder) {
        const outcome = await oauthMock.responder(accessToken, url);
        if (outcome instanceof Error) throw outcome;
        return outcome;
      }
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
  oauthMock.responder = null;
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

describe("toAuthenticatedFetch — concurrent-401 refresh coalescing (single-flight + freshest-wins)", () => {
  it("coalesces N simultaneous 401s into exactly ONE refresh and retries all with the fresh token", async () => {
    // Three requests fire concurrently, ALL get a bare 401, then ALL succeed on retry. The
    // single shared in-flight refresh must run exactly ONCE and every retry must use the fresh
    // credential — no per-request refresh, no stale-token reuse.
    oauthMock.behaviours.push(
      resp401(),
      resp401(),
      resp401(), // the three initial sends all 401
      resp200("retry-a"),
      resp200("retry-b"),
      resp200("retry-c"), // the three retries succeed
    );
    const freshHandle = fakeHandle("handle-2");
    let refreshCalls = 0;
    const refresh = vi.fn(async () => {
      refreshCalls += 1;
      // Yield so all three 401'd requests are awaiting before this resolves — proving the
      // coalescing holds them on ONE promise rather than each firing its own refresh.
      await Promise.resolve();
      return { accessToken: "access-2", dpopHandle: freshHandle };
    });

    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    const [a, b, c] = await Promise.all([
      authed("https://pod.example/a"),
      authed("https://pod.example/b"),
      authed("https://pod.example/c"),
    ]);

    // Exactly one refresh despite three concurrent 401s.
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(refreshCalls).toBe(1);

    // All three retries used the FRESH token + handle (never the stale "access-1").
    const retries = oauthMock.calls.slice(3);
    expect(retries).toHaveLength(3);
    for (const call of retries) {
      expect(call.accessToken).toBe("access-2");
      expect(call.options.DPoP).toBe(freshHandle);
    }

    // All three requests resolved to their fresh-token retry response.
    expect(await a.text()).toBe("retry-a");
    expect(await b.text()).toBe("retry-b");
    expect(await c.text()).toBe("retry-c");
    // 3 initial sends + 3 retries, no extra refresh-driven sends.
    expect(oauthMock.calls).toHaveLength(6);
  });

  it("freshest credential wins — a concurrent 401'd request that joins after the refresh lands retries with the fresh token (cred only moves forward)", async () => {
    // R1 401s and starts the refresh; while it is in flight R2 also 401s with the SAME stale
    // credential and JOINS the one refresh. Both must retry with the fresh token; the stale
    // "access-1" must never be reused after the refresh resolved.
    oauthMock.behaviours.push(resp401(), resp401(), resp200("r1"), resp200("r2"));
    const freshHandle = fakeHandle("h2");
    const refresh = vi.fn(async () => {
      await Promise.resolve();
      return { accessToken: "access-2", dpopHandle: freshHandle };
    });

    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    const [r1, r2] = await Promise.all([
      authed("https://pod.example/1"),
      authed("https://pod.example/2"),
    ]);

    expect(refresh).toHaveBeenCalledTimes(1); // single-flight: one refresh for both
    // Neither retry used the stale token; both moved forward to access-2.
    const retries = oauthMock.calls.slice(2);
    expect(retries.map((c) => c.accessToken)).toEqual(["access-2", "access-2"]);
    expect(await r1.text()).toBe("r1");
    expect(await r2.text()).toBe("r2");
  });

  it("THROWN invalid_token whose cred a peer ALREADY advanced → NO redundant refresh, retries with the fresh token (not the stale one)", async () => {
    // The thrown-401 path must use the SAME snapshot discipline as the returned-401 path: it
    // must compare-and-set against the credential the FAILED SEND used (captured per-attempt as
    // `lastSendCred`), NOT the live `cred` — which a peer's refresh may have ALREADY advanced
    // between R2's send and R2's failure-handling. Otherwise a request that THREW with an OLD
    // token, when handled, would compare the stale failure against a fresh `cred`, mis-detect it,
    // and fire a SECOND redundant refresh. This test is engineered so the bug DISTINGUISHES from
    // the fix: R1's refresh FULLY LANDS (cred → access-2) BEFORE R2's thrown-401 is handled.
    //
    // Deterministic sequence via a gated, (token,url)-keyed responder (no FIFO-order reliance):
    //   1. R2 SENDS with the stale access-1 → the responder records the send but PARKS the throw
    //      on `r2ThrowGate` (so R2's failure is delayed until we choose).
    //   2. R1 SENDS with the stale access-1 → returned bare-401 → R1 starts + COMPLETES the one
    //      refresh (cred → access-2), then R1 RETRIES with access-2 → 200.
    //   3. ONLY THEN do we release `r2ThrowGate`: R2's send finally REJECTS with invalid_token,
    //      handled while cred is ALREADY access-2 but `lastSendCred` is still access-1.
    //   4. The fix's compare-and-set (cred !== lastSendCred) → SHORT-CIRCUITS the refresh and
    //      retries R2 with access-2. The BUG (reading live `cred`) would call refreshAndRetry
    //      with the fresh `cred`, hit `cred === usedCred`, and fire a SECOND refresh.
    // So `refresh` called EXACTLY ONCE is the load-bearing fix-vs-bug discriminator.
    let releaseR2Throw: () => void = () => {};
    const r2ThrowGate = new Promise<void>((r) => {
      releaseR2Throw = r;
    });
    let refreshCalls = 0;
    const freshHandle = fakeHandle("h2");
    const refresh = vi.fn(async () => {
      refreshCalls += 1;
      return { accessToken: "access-2", dpopHandle: freshHandle };
    });

    oauthMock.responder = async (accessToken: string, url: URL): Promise<Response | Error> => {
      if (accessToken === "access-2") return resp200(`fresh:${url.pathname}`);
      // Stale access-1: /1 (R1) returns a bare-401; /2 (R2) THROWS — but only LATER, once the
      // gate releases (after R1's refresh has fully landed and cred advanced to access-2).
      if (url.pathname === "/2") {
        await r2ThrowGate; // PARK R2's send until we release it post-R1-refresh
        return challenge(401);
      }
      return resp401();
    };

    const authed = toAuthenticatedFetch(makeSession(), { refresh });

    // Start R2 first so its send is dispatched (with the stale access-1) and parked on the gate.
    const r2Promise = authed("https://pod.example/2");
    // Let R2's send dispatch (record the call) before R1 runs.
    await Promise.resolve();
    await Promise.resolve();

    // Drive R1 fully: 401 → the single refresh lands (cred → access-2) → retry → 200.
    const r1 = await authed("https://pod.example/1");
    expect(r1.status).toBe(200);
    expect(await r1.text()).toBe("fresh:/1");
    expect(refreshCalls).toBe(1); // R1 caused the one refresh; cred is now access-2

    // NOW release R2's throw: it is handled while cred(access-2) !== its snapshot(access-1).
    releaseR2Throw();
    const r2 = await r2Promise;

    // The fix: R2 SHORT-CIRCUITS (no second refresh) and retries with the fresh access-2.
    expect(r2.status).toBe(200);
    expect(await r2.text()).toBe("fresh:/2");

    // THE DISCRIMINATOR: exactly ONE refresh. The bug (live-`cred` read) would make this 2.
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(refreshCalls).toBe(1);

    // R2's FAILED send used the STALE access-1 (its compare-against snapshot).
    const r2FailedSend = oauthMock.calls.find(
      (c) => c.url.pathname === "/2" && c.accessToken === "access-1",
    );
    expect(r2FailedSend).toBeDefined();
    // R2's RETRY used the fresh access-2 + fresh handle — snapshot-aware reuse, never stale reuse.
    const r2Retry = oauthMock.calls.find(
      (c) => c.url.pathname === "/2" && c.accessToken === "access-2",
    );
    expect(r2Retry).toBeDefined();
    expect(r2Retry?.options.DPoP).toBe(freshHandle);
  });

  it("a refresh genuinely starts again only AFTER the first one settled (later expiry → new refresh)", async () => {
    // Request 1: 401 → refresh#1 → 200. Then, later, request 2: 401 again (token expired
    // again) → refresh#2 → 200. The in-flight slot must clear after #1 so #2 can refresh.
    oauthMock.behaviours.push(
      resp401(),
      resp200("first-ok"), // req1: 401 then refreshed-ok
      resp401(),
      resp200("second-ok"), // req2: 401 then refreshed-ok again
    );
    let n = 1;
    const refresh = vi.fn(async () => ({
      accessToken: `access-${++n}`,
      dpopHandle: fakeHandle(`h${n}`),
    }));

    const authed = toAuthenticatedFetch(makeSession(), { refresh });
    expect(await (await authed("https://pod.example/1")).text()).toBe("first-ok");
    expect(await (await authed("https://pod.example/2")).text()).toBe("second-ok");

    expect(refresh).toHaveBeenCalledTimes(2); // two SEQUENTIAL refreshes, not coalesced
    expect(callAt(1).accessToken).toBe("access-2"); // req1 retry token
    expect(callAt(3).accessToken).toBe("access-3"); // req2 retry token (fresher still)
  });
});

describe("toAuthenticatedFetch — DPoP-nonce retry bounded to ONE per invocation (not per send-attempt)", () => {
  it("does NOT allow a second nonce retry after a token refresh (one nonce retry per call)", async () => {
    // Send 1 → nonce challenge → nonce retry (send 2) → 401 → refresh → retry (send 3) →
    // nonce challenge AGAIN. With the budget bounded per INVOCATION, send 3's nonce error is
    // terminal (no send 4): the per-call nonce budget was already spent before the refresh.
    const nonce1 = challenge(400);
    const nonce2 = challenge(400);
    oauthMock.nonceErrors.add(nonce1);
    oauthMock.nonceErrors.add(nonce2);
    oauthMock.behaviours.push(
      nonce1, // send 1: nonce challenge
      resp401(), // send 2 (nonce retry): 401 → triggers refresh
      nonce2, // send 3 (post-refresh retry): nonce challenge again
    );
    const refresh = vi.fn(async () => ({ accessToken: "access-2", dpopHandle: fakeHandle("h2") }));
    const authed = toAuthenticatedFetch(makeSession(), { refresh });

    // The post-refresh nonce error is not a token-expiry, so it RETHROWS (not masked as 401)
    // — and crucially there is NO fourth send (the nonce budget is one per the whole call).
    await expect(authed("https://pod.example/x")).rejects.toBe(nonce2);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(oauthMock.calls).toHaveLength(3); // send1 + nonce-retry + post-refresh send, no 4th
  });

  it("still allows the single nonce retry when it happens AFTER the refresh (budget unspent before)", async () => {
    // Send 1 → 401 → refresh → retry (send 2) → nonce challenge → nonce retry (send 3) → 200.
    // The nonce budget was untouched before the refresh, so the one nonce retry is available
    // on the post-refresh send.
    const nonceErr = challenge(400);
    oauthMock.nonceErrors.add(nonceErr);
    oauthMock.behaviours.push(
      resp401(), // send 1: 401 → refresh
      nonceErr, // send 2 (post-refresh): nonce challenge
      resp200("after-post-refresh-nonce"), // send 3: nonce retry succeeds
    );
    const refresh = vi.fn(async () => ({ accessToken: "access-2", dpopHandle: fakeHandle("h2") }));
    const authed = toAuthenticatedFetch(makeSession(), { refresh });

    const res = await authed("https://pod.example/x");
    expect(await res.text()).toBe("after-post-refresh-nonce");
    expect(oauthMock.calls).toHaveLength(3);
    expect(callAt(2).accessToken).toBe("access-2"); // the nonce retry used the fresh token
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
