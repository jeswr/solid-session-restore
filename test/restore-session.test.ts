// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// Exhaustive, security-critical tests for the standalone DPoP-bound refresh-token
// restore — the helper that lets a CLOSED-TAB REOPEN re-establish the session with
// NO popup/iframe. Ported from the pod-mail pilot's provider-half restore tests.
//
// What is pinned here (the adversarial matrix):
//   • restoreSession rebuilds the session via a refresh_token grant (a fetch) and
//     reports the WebID + the rebuilt access token;
//   • the refresh grant is DPoP-bound (a DPoP handle is passed) and signed by the
//     SAME persisted key the original token was bound to (key continuity);
//   • the refresh token redeemed is THAT issuer's token only (per-issuer credential);
//   • a DEAD refresh token (invalid_grant) → undefined AND the dead entry is CLEARED;
//   • a TRANSIENT failure (NOT invalid_grant) → undefined but PRESERVES the credential;
//   • the server-ROTATED refresh token is re-persisted (next reload uses the current
//     credential, not a spent one), and the access token is NEVER persisted;
//   • a DPoP-nonce challenge is retried once (RFC 9449 nonce handshake);
//   • no persisted session / no store entry → undefined, NO grant attempted;
//   • forgetPersisted / clearPersisted drop the durable credential (logout);
//   • hasPersisted is a tri-state (present / absent / unknown) — a store-read error
//     is `unknown`, never `absent` (so the caller keeps the pointer under uncertainty);
//   • WebID SCOPING: a restore for B's issuer leaves A's persisted entry untouched.
//
// The whole OAuth/DPoP stack is mocked so this runs with no browser + no network.
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { PersistedSession, SessionStore } from "../src/session-persistence.js";

// A switch each test sets so the next refresh "returns" a chosen identity/token.
const authState = {
  webId: "https://alice.example/profile/card#me",
  refreshTokenRotated: "rt-rotated" as string | undefined,
};

// Capture the DPoP handle passed into the refresh grant so a test can assert the
// grant is DPoP-bound (proof-of-possession, not bare Bearer), plus a nonce switch.
const refreshMock = vi.hoisted(() => ({
  grantOpts: [] as Array<{ DPoP?: unknown }>,
  grantTokens: [] as string[],
  // The client_id the grant ran as (asserts client-binding — finding 1).
  grantClientIds: [] as Array<string | undefined>,
  // How many times a FRESH dynamic registration was attempted (should be 0 when a
  // client id is known — a refresh token is client-bound, RFC 6749 §6).
  dynamicRegistrations: 0,
  // When set, the next refreshTokenGrantRequest rejects (a dead/transient token).
  reject: null as Error | null,
  // When true, the FIRST grant throws a DPoP-nonce error (retried once).
  nonceOnce: false,
  nonceThrown: false,
  // The DPoP handle the helper built for the refresh (asserts key continuity).
  lastDpopHandle: null as unknown,
  // The client-auth function passed into each grant (arg index 2) — asserts WHICH
  // auth method (none / client_secret_basic / client_secret_post) the helper chose.
  grantClientAuths: [] as unknown[],
  // What the dynamic-registration RESPONSE advertises (so a test can drive an
  // ESS-style `client_secret_basic` fresh registration).
  registrationResponse: {
    client_id: "freshly-registered-client",
    token_endpoint_auth_method: "none",
  } as {
    client_id: string;
    token_endpoint_auth_method?: string;
    client_secret?: string;
  },
  // The discovered issuer (the ESS no-url-encode workaround keys off this). Default
  // is a non-ESS issuer; an ESS test sets it to a login.inrupt.com URL.
  discoveredIssuer: "https://issuer.example/",
}));

vi.mock("oauth4webapi", () => {
  const allowInsecureRequests = Symbol("allowInsecureRequests");
  const customFetch = Symbol("customFetch");
  class DPoPNonceError extends Error {}
  return {
    allowInsecureRequests,
    customFetch,
    // Tagged client-auth constructors so a test can identify WHICH method the helper
    // chose (and, for client_secret_post, the secret it carried). `None` returns a
    // distinct tagged value too. The ESS no-url-encode variant is built LOCALLY in
    // restore-session.ts (NOT via these), so for an ESS issuer the captured clientAuth
    // is a plain function, not one of these tags — which a test relies on.
    None: () => ({ method: "none" }) as unknown,
    ClientSecretBasic: (secret: string) => ({ method: "client_secret_basic", secret }) as unknown,
    ClientSecretPost: (secret: string) => ({ method: "client_secret_post", secret }) as unknown,
    expectNoNonce: Symbol("expectNoNonce"),
    // DPoP() returns a tagged handle so tests can recognise the SAME handle reused.
    DPoP: vi.fn((_client: unknown, key: unknown) => {
      const handle = { dpopMarker: true, key };
      refreshMock.lastDpopHandle = handle;
      return handle;
    }),
    isDPoPNonceError: (e: unknown) => e instanceof DPoPNonceError,
    discoveryRequest: vi.fn(async () => ({})),
    processDiscoveryResponse: vi.fn(async () => ({
      issuer: refreshMock.discoveredIssuer,
      authorization_endpoint: `${refreshMock.discoveredIssuer}auth`,
      token_endpoint: `${refreshMock.discoveredIssuer}token`,
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["openid", "webid", "offline_access"],
    })),
    dynamicClientRegistrationRequest: vi.fn(async () => {
      refreshMock.dynamicRegistrations += 1;
      return {};
    }),
    processDynamicClientRegistrationResponse: vi.fn(async () => refreshMock.registrationResponse),
    refreshTokenGrantRequest: vi.fn(async (..._args: unknown[]) => {
      // arg index 1 is the client; index 2 the clientAuth; index 3 the refresh token;
      // index 4 the options.
      refreshMock.grantClientIds.push((_args[1] as { client_id?: string } | undefined)?.client_id);
      refreshMock.grantClientAuths.push(_args[2]);
      refreshMock.grantTokens.push(_args[3] as string);
      refreshMock.grantOpts.push((_args[4] as { DPoP?: unknown }) ?? {});
      if (refreshMock.nonceOnce && !refreshMock.nonceThrown) {
        refreshMock.nonceThrown = true;
        throw new DPoPNonceError("use a DPoP nonce");
      }
      if (refreshMock.reject) throw refreshMock.reject;
      return {};
    }),
    processRefreshTokenResponse: vi.fn(async () => ({
      access_token: "tok-refreshed",
      refresh_token: authState.refreshTokenRotated,
      expires_in: 3600,
    })),
    getValidatedIdTokenClaims: vi.fn(() => ({
      iss: "https://issuer.example/",
      sub: authState.webId,
      webid: authState.webId,
      aud: "client",
      iat: 0,
      exp: 0,
    })),
  };
});

const { restoreSession, hasPersisted, forgetPersisted, clearPersisted, isInvalidGrantError } =
  await import("../src/restore-session.js");

const WEBID_A = "https://alice.example/profile/card#me";
const WEBID_B = "https://bob.example/profile/card#me";
const ISSUER = new URL("https://issuer.example/");

/** A simple in-memory SessionStore double, keyed by issuer (mirrors IndexedDB). */
function makeStore(): SessionStore & { map: Map<string, PersistedSession> } {
  const map = new Map<string, PersistedSession>();
  return {
    map,
    async get(issuer) {
      return map.get(issuer);
    },
    async put(session) {
      map.set(session.issuer, session);
    },
    async delete(issuer) {
      map.delete(issuer);
    },
  };
}

const sampleKey = async (): Promise<CryptoKeyPair> =>
  (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

async function seed(
  store: ReturnType<typeof makeStore>,
  overrides: Partial<PersistedSession> = {},
): Promise<CryptoKeyPair> {
  const dpopKey = await sampleKey();
  store.map.set(ISSUER.href, {
    issuer: ISSUER.href,
    webId: WEBID_A,
    refreshToken: "rt-A",
    dpopKey,
    clientId: "https://app.example/clientid.jsonld",
    ...overrides,
  });
  return dpopKey;
}

const CLIENT_OPTS = { clientId: "https://app.example/clientid.jsonld" } as const;

beforeEach(() => {
  authState.webId = WEBID_A;
  authState.refreshTokenRotated = "rt-rotated";
  refreshMock.grantOpts.length = 0;
  refreshMock.grantTokens.length = 0;
  refreshMock.grantClientIds.length = 0;
  refreshMock.dynamicRegistrations = 0;
  refreshMock.reject = null;
  refreshMock.nonceOnce = false;
  refreshMock.nonceThrown = false;
  refreshMock.lastDpopHandle = null;
  refreshMock.grantClientAuths.length = 0;
  refreshMock.registrationResponse = {
    client_id: "freshly-registered-client",
    token_endpoint_auth_method: "none",
  };
  refreshMock.discoveredIssuer = "https://issuer.example/";
});

describe("restoreSession — silent refresh-token-grant restore (no popup)", () => {
  it("rebuilds the session from a persisted refresh token and reports the WebID + access token", async () => {
    const store = makeStore();
    await seed(store);
    const oauth = await import("oauth4webapi");
    const before = (oauth.refreshTokenGrantRequest as ReturnType<typeof vi.fn>).mock.calls.length;
    const restored = await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS });
    expect(restored?.webId).toBe(WEBID_A);
    expect(restored?.accessToken).toBe("tok-refreshed");
    expect(restored?.issuer).toBe(ISSUER.href);
    // The refresh grant ran exactly once (a fetch) — NO popup was opened.
    const after = (oauth.refreshTokenGrantRequest as ReturnType<typeof vi.fn>).mock.calls.length;
    expect(after).toBe(before + 1);
  });

  it("the restore is DPoP-BOUND (a DPoP handle is passed — not bare Bearer) and key-continuous", async () => {
    const store = makeStore();
    const dpopKey = await seed(store);
    const restored = await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS });

    // The grant carried a DPoP handle, and it is the SAME handle the helper built
    // around the PERSISTED key (key continuity — RFC 9449 §4.3 sender-constraining).
    expect(refreshMock.grantOpts).toHaveLength(1);
    expect(refreshMock.grantOpts[0]?.DPoP).toBeDefined();
    expect(refreshMock.grantOpts[0]?.DPoP).toBe(refreshMock.lastDpopHandle);
    expect((refreshMock.lastDpopHandle as { key: unknown }).key).toBe(dpopKey);
    // The restored session exposes the same key + handle for subsequent calls.
    expect(restored?.dpopKey).toBe(dpopKey);
    expect(restored?.dpopHandle).toBe(refreshMock.lastDpopHandle);
  });

  it("redeems THAT issuer's token only (per-issuer credential)", async () => {
    const store = makeStore();
    await seed(store);
    await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS });
    expect(refreshMock.grantTokens).toEqual(["rt-A"]); // A's token — never another account's
  });

  it("re-persists the ROTATED refresh token (the next reload uses the current credential)", async () => {
    const store = makeStore();
    await seed(store);
    await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS });
    // processRefreshTokenResponse rotated the token to "rt-rotated"; it must be the
    // persisted credential now (a spent "rt-A" would be rejected on the next load).
    expect(store.map.get(ISSUER.href)?.refreshToken).toBe("rt-rotated");
  });

  it("keeps the OLD refresh token when the server does not rotate", async () => {
    const store = makeStore();
    await seed(store);
    authState.refreshTokenRotated = undefined; // server issued no new refresh token
    const restored = await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS });
    expect(restored?.refreshToken).toBe("rt-A");
    expect(store.map.get(ISSUER.href)?.refreshToken).toBe("rt-A");
  });

  it("NEVER persists the access token (only the long-lived key-bound credential)", async () => {
    const store = makeStore();
    await seed(store);
    await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS });
    const persisted = store.map.get(ISSUER.href) as unknown as Record<string, unknown>;
    expect(persisted.accessToken).toBeUndefined();
    expect(JSON.stringify({ ...persisted, dpopKey: undefined })).not.toContain("tok-refreshed");
  });

  it("retries ONCE on a server-required DPoP nonce (RFC 9449 nonce handshake)", async () => {
    const store = makeStore();
    await seed(store);
    refreshMock.nonceOnce = true; // the first grant throws a DPoP-nonce error
    const restored = await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS });
    expect(restored?.accessToken).toBe("tok-refreshed");
    // Two grant attempts: the nonce-challenged one + the retry.
    expect(refreshMock.grantOpts).toHaveLength(2);
  });

  it("returns undefined + does NOT attempt a refresh grant when there is NO persisted session", async () => {
    const store = makeStore();
    const oauth = await import("oauth4webapi");
    const before = (oauth.refreshTokenGrantRequest as ReturnType<typeof vi.fn>).mock.calls.length;
    expect(await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS })).toBeUndefined();
    const after = (oauth.refreshTokenGrantRequest as ReturnType<typeof vi.fn>).mock.calls.length;
    expect(after).toBe(before); // no grant attempted (nothing to restore)
  });

  it("returns undefined when the persisted entry has an EMPTY refresh token", async () => {
    const store = makeStore();
    await seed(store, { refreshToken: "" });
    expect(await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS })).toBeUndefined();
    expect(refreshMock.grantTokens).toHaveLength(0);
  });

  it("returns undefined (fail-closed) when the store READ throws — no grant, stays silent", async () => {
    const throwingStore: SessionStore = {
      get: async () => {
        throw new Error("IndexedDB read failed");
      },
      put: async () => {},
      delete: async () => {},
    };
    expect(
      await restoreSession({ store: throwingStore, issuer: ISSUER, ...CLIENT_OPTS }),
    ).toBeUndefined();
    expect(refreshMock.grantTokens).toHaveLength(0);
  });

  it("a DEAD refresh token (invalid_grant) → undefined AND the dead entry is CLEARED (no popup on restore)", async () => {
    const store = makeStore();
    await seed(store);
    // oauth4webapi surfaces a token-endpoint OAuth error as a ResponseBodyError-shape
    // carrying `.error` — invalid_grant = expired / revoked / rotation-reuse.
    refreshMock.reject = Object.assign(new Error("invalid_grant"), { error: "invalid_grant" });

    const restored = await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS });
    expect(restored).toBeUndefined();
    // The dead entry was cleared so a doomed restore is not re-attempted next load.
    expect(store.map.has(ISSUER.href)).toBe(false);
  });

  it("invalid_grant nested under .cause.parameters is also recognised and CLEARS the entry", async () => {
    const store = makeStore();
    await seed(store);
    refreshMock.reject = Object.assign(new Error("grant rejected"), {
      cause: { parameters: new URLSearchParams({ error: "invalid_grant" }) },
    });
    expect(await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS })).toBeUndefined();
    expect(store.map.has(ISSUER.href)).toBe(false);
  });

  it("a TRANSIENT failure (NOT invalid_grant) → undefined but PRESERVES the credential", async () => {
    // A network/discovery/5xx blip on load must NOT erase an otherwise-valid refresh
    // token — that would force a needless re-login. The entry survives for a retry;
    // THIS load just falls back to login (silently — no popup on restore).
    const store = makeStore();
    await seed(store);
    refreshMock.reject = new Error("network timeout"); // transient, no OAuth error field

    const restored = await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS });
    expect(restored).toBeUndefined();
    // The credential is PRESERVED — a transient error did not wipe a valid token.
    expect(store.map.get(ISSUER.href)?.refreshToken).toBe("rt-A");
  });

  it("a server OAuth error that is NOT invalid_grant (e.g. invalid_client) PRESERVES the credential", async () => {
    const store = makeStore();
    await seed(store);
    refreshMock.reject = Object.assign(new Error("invalid_client"), { error: "invalid_client" });
    expect(await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS })).toBeUndefined();
    expect(store.map.get(ISSUER.href)?.refreshToken).toBe("rt-A"); // not cleared
  });
});

describe("client-binding — a refresh token is redeemed as its OWN client (roborev finding 1)", () => {
  it("runs the grant as the STATIC clientId when options.clientId is supplied (no re-registration)", async () => {
    const store = makeStore();
    await seed(store); // stored.clientId = the static clientid.jsonld
    await restoreSession({
      store,
      issuer: ISSUER,
      clientId: "https://app.example/clientid.jsonld",
    });
    expect(refreshMock.grantClientIds).toEqual(["https://app.example/clientid.jsonld"]);
    expect(refreshMock.dynamicRegistrations).toBe(0);
  });

  it("REUSES the PERSISTED clientId for a dynamic-login restore (does NOT re-register a fresh client)", async () => {
    // A dynamic login persisted its server-assigned client_id. On restore — with NO
    // options.clientId — the grant MUST run as that persisted client (a refresh token
    // is client-bound); registering a fresh client would fail invalid_client.
    const store = makeStore();
    await seed(store, { clientId: "server-assigned-dynamic-client-id" });
    const restored = await restoreSession({ store, issuer: ISSUER }); // no options.clientId
    expect(restored?.webId).toBe(WEBID_A);
    expect(refreshMock.grantClientIds).toEqual(["server-assigned-dynamic-client-id"]);
    // The bug this guards: a fresh dynamic registration on every restore.
    expect(refreshMock.dynamicRegistrations).toBe(0);
  });

  it("options.clientId takes precedence over a stored clientId (the app re-pins its static id)", async () => {
    const store = makeStore();
    await seed(store, { clientId: "stale-stored-id" });
    await restoreSession({
      store,
      issuer: ISSUER,
      clientId: "https://app.example/clientid.jsonld",
    });
    expect(refreshMock.grantClientIds).toEqual(["https://app.example/clientid.jsonld"]);
    expect(refreshMock.dynamicRegistrations).toBe(0);
  });

  it("falls back to a FRESH dynamic registration ONLY when neither option nor stored clientId exists", async () => {
    const store = makeStore();
    // Seed an entry with NO clientId field at all (a dynamic login that never
    // persisted its client id — the only case a fresh registration is justified).
    store.map.set(ISSUER.href, {
      issuer: ISSUER.href,
      webId: WEBID_A,
      refreshToken: "rt-A",
      dpopKey: await sampleKey(),
    });
    const restored = await restoreSession({ store, issuer: ISSUER }); // no options.clientId
    expect(restored?.webId).toBe(WEBID_A);
    // The only path that legitimately registers fresh.
    expect(refreshMock.dynamicRegistrations).toBe(1);
    expect(refreshMock.grantClientIds).toEqual(["freshly-registered-client"]);
  });
});

describe("client authentication — public default + confidential client_secret (issue #1)", () => {
  it("PUBLIC client (no secret) authenticates the grant with `none` — the unchanged default", async () => {
    const store = makeStore();
    await seed(store); // no tokenEndpointAuthMethod / clientSecret persisted
    const restored = await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS });
    expect(restored?.webId).toBe(WEBID_A);
    // The grant ran with `none` client auth (no secret), exactly as before.
    expect(refreshMock.grantClientAuths).toHaveLength(1);
    expect(refreshMock.grantClientAuths[0]).toEqual({ method: "none" });
    // A public client persists NO secret on the rotated re-persist.
    const persisted = store.map.get(ISSUER.href);
    expect(persisted?.clientSecret).toBeUndefined();
    expect(persisted?.tokenEndpointAuthMethod).toBeUndefined();
  });

  it("CONFIDENTIAL client (persisted client_secret_basic + secret) authenticates via Basic with the secret", async () => {
    const store = makeStore();
    await seed(store, {
      tokenEndpointAuthMethod: "client_secret_basic",
      clientSecret: "s3cr3t",
      clientId: "server-assigned-dynamic-client-id",
    });
    const restored = await restoreSession({ store, issuer: ISSUER });
    expect(restored?.webId).toBe(WEBID_A);
    // The grant authenticated with the persisted secret via client_secret_basic.
    expect(refreshMock.grantClientAuths[0]).toEqual({
      method: "client_secret_basic",
      secret: "s3cr3t",
    });
  });

  it("CONFIDENTIAL client_secret_post sends the secret in the body (per the persisted method)", async () => {
    const store = makeStore();
    await seed(store, {
      tokenEndpointAuthMethod: "client_secret_post",
      clientSecret: "s3cr3t",
      clientId: "server-assigned-dynamic-client-id",
    });
    await restoreSession({ store, issuer: ISSUER });
    expect(refreshMock.grantClientAuths[0]).toEqual({
      method: "client_secret_post",
      secret: "s3cr3t",
    });
  });

  it("re-persists the confidential method + secret across a refresh-token ROTATION", async () => {
    const store = makeStore();
    await seed(store, {
      tokenEndpointAuthMethod: "client_secret_basic",
      clientSecret: "s3cr3t",
      clientId: "server-assigned-dynamic-client-id",
    });
    await restoreSession({ store, issuer: ISSUER });
    const persisted = store.map.get(ISSUER.href);
    // The rotated token re-persist carries the confidential creds forward so the NEXT
    // reload can authenticate the same way.
    expect(persisted?.refreshToken).toBe("rt-rotated");
    expect(persisted?.tokenEndpointAuthMethod).toBe("client_secret_basic");
    expect(persisted?.clientSecret).toBe("s3cr3t");
  });

  it("a FRESH ESS-style dynamic registration that returns client_secret_basic is adopted + persisted", async () => {
    // The headline issue-#1 case: a dynamic login whose registration came back
    // confidential (ESS/PodSpaces). The session never persisted a clientId, so a
    // fresh registration runs; the helper must ADOPT the returned secret + method,
    // authenticate the grant with it, and persist it for the next reload.
    const store = makeStore();
    store.map.set(ISSUER.href, {
      issuer: ISSUER.href,
      webId: WEBID_A,
      refreshToken: "rt-A",
      dpopKey: await sampleKey(),
    });
    refreshMock.registrationResponse = {
      client_id: "ess-dynamic-client",
      token_endpoint_auth_method: "client_secret_basic",
      client_secret: "ess-secret",
    };
    const restored = await restoreSession({ store, issuer: ISSUER }); // no options.clientId
    expect(restored?.webId).toBe(WEBID_A);
    expect(refreshMock.dynamicRegistrations).toBe(1);
    // The grant authenticated with the freshly-registered confidential secret (non-ESS
    // issuer here → the standard ClientSecretBasic tag, not the no-url-encode variant).
    expect(refreshMock.grantClientAuths[0]).toEqual({
      method: "client_secret_basic",
      secret: "ess-secret",
    });
    // And it is persisted so the next reload restores confidentially without re-registering.
    const persisted = store.map.get(ISSUER.href);
    expect(persisted?.tokenEndpointAuthMethod).toBe("client_secret_basic");
    expect(persisted?.clientSecret).toBe("ess-secret");
    // The SERVER-ASSIGNED client_id is persisted too (refresh tokens are client-bound —
    // RFC 6749 §6); without it the next reload re-registers a fresh client and orphans
    // the persisted secret (roborev High finding).
    expect(persisted?.clientId).toBe("ess-dynamic-client");
  });

  it("persists the SERVER-ASSIGNED client_id from a fresh PUBLIC dynamic registration (client-binding)", async () => {
    // Even for a `none` fresh registration the resolved client_id must be persisted so
    // the next reload reuses the same client (the refresh token is client-bound). This
    // is the public-client half of the roborev High finding.
    const store = makeStore();
    store.map.set(ISSUER.href, {
      issuer: ISSUER.href,
      webId: WEBID_A,
      refreshToken: "rt-A",
      dpopKey: await sampleKey(),
    });
    // Default registrationResponse is { client_id: "freshly-registered-client", none }.
    await restoreSession({ store, issuer: ISSUER });
    expect(refreshMock.dynamicRegistrations).toBe(1);
    expect(store.map.get(ISSUER.href)?.clientId).toBe("freshly-registered-client");
  });

  it("a fresh registration with a secret but OMITTED method defaults to client_secret_basic (OIDC/RFC 7591)", async () => {
    // OIDC Registration 1.0 / RFC 7591 §2 default an omitted token_endpoint_auth_method
    // to client_secret_basic. A secret-bearing registration with no method must NOT be
    // treated as `none` (that would skip required client auth — roborev Medium).
    const store = makeStore();
    store.map.set(ISSUER.href, {
      issuer: ISSUER.href,
      webId: WEBID_A,
      refreshToken: "rt-A",
      dpopKey: await sampleKey(),
    });
    refreshMock.registrationResponse = {
      client_id: "ess-dynamic-client",
      client_secret: "ess-secret",
      // token_endpoint_auth_method intentionally OMITTED
    };
    const restored = await restoreSession({ store, issuer: ISSUER });
    expect(restored?.webId).toBe(WEBID_A);
    expect(refreshMock.grantClientAuths[0]).toEqual({
      method: "client_secret_basic",
      secret: "ess-secret",
    });
    const persisted = store.map.get(ISSUER.href);
    expect(persisted?.tokenEndpointAuthMethod).toBe("client_secret_basic");
    expect(persisted?.clientSecret).toBe("ess-secret");
  });

  it("FAIL-CLOSED: a fresh registration issuing a secret under an UNSUPPORTED method → undefined, no grant", async () => {
    // A registration that hands back a secret but asks for a method we cannot honour
    // (e.g. client_secret_jwt / private_key_jwt) must FAIL CLOSED, never silently
    // downgrade to `none` and send the credential the wrong way.
    const store = makeStore();
    store.map.set(ISSUER.href, {
      issuer: ISSUER.href,
      webId: WEBID_A,
      refreshToken: "rt-A",
      dpopKey: await sampleKey(),
    });
    refreshMock.registrationResponse = {
      client_id: "ess-dynamic-client",
      client_secret: "ess-secret",
      token_endpoint_auth_method: "client_secret_jwt",
    };
    const restored = await restoreSession({ store, issuer: ISSUER });
    expect(restored).toBeUndefined();
    expect(refreshMock.grantClientAuths).toHaveLength(0);
    // Credential preserved (a method we can't honour is not proof the token is dead).
    expect(store.map.get(ISSUER.href)?.refreshToken).toBe("rt-A");
  });

  it("FAIL-CLOSED: a fresh registration with an UNSUPPORTED method and NO secret also aborts (not `none`)", async () => {
    // A server that registers us with private_key_jwt / tls_client_auth and issues NO
    // secret must NOT be silently treated as a public `none` client — that would
    // mis-authenticate. Fail closed even with no secret present (roborev finding).
    const store = makeStore();
    store.map.set(ISSUER.href, {
      issuer: ISSUER.href,
      webId: WEBID_A,
      refreshToken: "rt-A",
      dpopKey: await sampleKey(),
    });
    refreshMock.registrationResponse = {
      client_id: "strong-auth-client",
      token_endpoint_auth_method: "private_key_jwt",
      // no client_secret
    };
    const restored = await restoreSession({ store, issuer: ISSUER });
    expect(restored).toBeUndefined();
    expect(refreshMock.grantClientAuths).toHaveLength(0);
    expect(store.map.get(ISSUER.href)?.refreshToken).toBe("rt-A");
  });

  it("persists the SERVER-ASSIGNED client_id when the stored clientId is an EMPTY STRING (treated as absent)", async () => {
    // resolveClient treats an empty stored clientId as absent (→ fresh registration);
    // the rotation re-persist must do the same and NOT preserve the empty string,
    // otherwise the server-assigned id is dropped (roborev finding).
    const store = makeStore();
    store.map.set(ISSUER.href, {
      issuer: ISSUER.href,
      webId: WEBID_A,
      refreshToken: "rt-A",
      dpopKey: await sampleKey(),
      clientId: "", // empty → absent
    });
    await restoreSession({ store, issuer: ISSUER });
    expect(refreshMock.dynamicRegistrations).toBe(1);
    expect(store.map.get(ISSUER.href)?.clientId).toBe("freshly-registered-client");
  });

  it("does NOT apply the ESS no-url-encode workaround to an issuer that merely CONTAINS the substring", async () => {
    // The workaround is keyed on the EXACT hostname, so an unrelated issuer whose URL
    // only contains `login.inrupt.com` as a path/subdomain segment uses the SPEC
    // ClientSecretBasic, not the bespoke variant (roborev finding).
    const store = makeStore();
    const lookalike = new URL("https://evil.example/login.inrupt.com/oidc");
    refreshMock.discoveredIssuer = "https://evil.example/login.inrupt.com/oidc/";
    store.map.set(lookalike.href, {
      issuer: lookalike.href,
      webId: WEBID_A,
      refreshToken: "rt-A",
      dpopKey: await sampleKey(),
      tokenEndpointAuthMethod: "client_secret_basic",
      clientSecret: "s3cr3t",
      clientId: "some-client",
    });
    await restoreSession({ store, issuer: lookalike });
    // The SPEC ClientSecretBasic tag (the mocked one), NOT the local no-url-encode fn.
    expect(refreshMock.grantClientAuths[0]).toEqual({
      method: "client_secret_basic",
      secret: "s3cr3t",
    });
  });

  it("an INRUPT-ESS issuer uses the BESPOKE no-url-encode Basic header (NOT the spec ClientSecretBasic)", async () => {
    // The ESS workaround: for login.inrupt.com the helper builds a LOCAL clientAuth
    // that base64s `client_id:secret` WITHOUT RFC-6749-§2.3.1 form-url-encoding. We
    // assert (a) it is NOT the mocked spec ClientSecretBasic tag, and (b) invoking it
    // produces the exact non-url-encoded Basic header.
    const store = makeStore();
    const essIssuer = new URL("https://login.inrupt.com/");
    refreshMock.discoveredIssuer = "https://login.inrupt.com/";
    // A client_id + secret containing chars that RFC form-url-encoding WOULD escape.
    // Seed under the ESS issuer key (the store is keyed by issuer).
    store.map.set(essIssuer.href, {
      issuer: essIssuer.href,
      webId: WEBID_A,
      refreshToken: "rt-A",
      dpopKey: await sampleKey(),
      tokenEndpointAuthMethod: "client_secret_basic",
      clientSecret: "se cr+et",
      clientId: "client id+1",
    });
    await restoreSession({ store, issuer: essIssuer });
    const clientAuth = refreshMock.grantClientAuths[0] as
      | ((as: unknown, client: { client_id: string }, body: unknown, headers: Headers) => void)
      | { method: string };
    // It is the LOCAL function, not the mocked spec tag.
    expect(typeof clientAuth).toBe("function");
    // Invoke it and confirm the raw (non-url-encoded) Basic header.
    const headers = new Headers();
    (
      clientAuth as (
        as: unknown,
        client: { client_id: string },
        body: unknown,
        headers: Headers,
      ) => void
    )({}, { client_id: "client id+1" }, new URLSearchParams(), headers);
    const expected = `Basic ${btoa("client id+1:se cr+et")}`;
    expect(headers.get("authorization")).toBe(expected);
  });

  it("an OPTION-supplied secret OVERRIDES a persisted one (app re-supplies a known secret)", async () => {
    const store = makeStore();
    await seed(store, {
      tokenEndpointAuthMethod: "client_secret_basic",
      clientSecret: "stale-persisted-secret",
      clientId: "server-assigned-dynamic-client-id",
    });
    await restoreSession({
      store,
      issuer: ISSUER,
      tokenEndpointAuthMethod: "client_secret_basic",
      clientSecret: "fresh-option-secret",
    });
    expect(refreshMock.grantClientAuths[0]).toEqual({
      method: "client_secret_basic",
      secret: "fresh-option-secret",
    });
  });

  it("FAIL-CLOSED: a confidential method with NO secret → undefined, NO grant, credential PRESERVED", async () => {
    // A corrupt/partial record asserts client_secret_basic but carries no secret. We
    // must NOT silently downgrade to `none` (which could mis-authenticate) — fail
    // closed: no grant, the refresh token is preserved (this is not proof it is dead).
    const store = makeStore();
    await seed(store, {
      tokenEndpointAuthMethod: "client_secret_basic",
      clientId: "server-assigned-dynamic-client-id",
      // clientSecret deliberately absent
    });
    const restored = await restoreSession({ store, issuer: ISSUER });
    expect(restored).toBeUndefined();
    // No grant was even attempted (we bailed before the token endpoint).
    expect(refreshMock.grantClientAuths).toHaveLength(0);
    expect(refreshMock.grantTokens).toHaveLength(0);
    // The credential is PRESERVED — a missing secret is not proof the token is dead.
    expect(store.map.get(ISSUER.href)?.refreshToken).toBe("rt-A");
  });

  it("FAIL-CLOSED: a confidential method with an EMPTY-STRING secret is also rejected", async () => {
    const store = makeStore();
    await seed(store, {
      tokenEndpointAuthMethod: "client_secret_basic",
      clientSecret: "",
      clientId: "server-assigned-dynamic-client-id",
    });
    expect(await restoreSession({ store, issuer: ISSUER })).toBeUndefined();
    expect(refreshMock.grantClientAuths).toHaveLength(0);
    expect(store.map.get(ISSUER.href)?.refreshToken).toBe("rt-A");
  });

  it("FAIL-CLOSED: a PERSISTED unsupported method (client_secret_jwt) aborts, not downgrades to `none`", async () => {
    // A corrupt/foreign store entry asserts a method we cannot honour. It must fail
    // closed exactly like the fresh-registration path — never be treated as public
    // `none` (which would skip the auth the record demanded) (roborev finding).
    const store = makeStore();
    await seed(store, {
      // cast through unknown: the store could hold any string at runtime.
      tokenEndpointAuthMethod: "client_secret_jwt" as unknown as "client_secret_basic",
      clientSecret: "s3cr3t",
      clientId: "server-assigned-dynamic-client-id",
    });
    const restored = await restoreSession({ store, issuer: ISSUER });
    expect(restored).toBeUndefined();
    expect(refreshMock.grantClientAuths).toHaveLength(0);
    expect(refreshMock.dynamicRegistrations).toBe(0); // a clientId was present — no re-register
    expect(store.map.get(ISSUER.href)?.refreshToken).toBe("rt-A"); // preserved
  });

  it("persists the RESOLVED client_id (option override), NOT a stale stored one (client-binding)", async () => {
    // When options.clientId overrides a stale persisted id, the rotated refresh token
    // is issued to the RESOLVED client — so that id, not the stale stored one, must be
    // persisted, else a later restore redeems the new token as the WRONG client (roborev
    // finding).
    const store = makeStore();
    await seed(store, { clientId: "stale-stored-id" });
    await restoreSession({
      store,
      issuer: ISSUER,
      clientId: "https://app.example/clientid.jsonld",
    });
    expect(refreshMock.grantClientIds).toEqual(["https://app.example/clientid.jsonld"]);
    expect(store.map.get(ISSUER.href)?.clientId).toBe("https://app.example/clientid.jsonld");
  });

  it("ignores a persisted secret when the method is `none` (never sends it) and does NOT re-persist it", async () => {
    // Defence-in-depth: a stray secret on a `none` record must not leak into the grant.
    const store = makeStore();
    await seed(store, {
      tokenEndpointAuthMethod: "none",
      clientSecret: "stray-secret",
      clientId: "server-assigned-dynamic-client-id",
    });
    await restoreSession({ store, issuer: ISSUER });
    expect(refreshMock.grantClientAuths[0]).toEqual({ method: "none" });
    // The rotated re-persist drops the stray secret (a `none` record stays secret-free).
    const persisted = store.map.get(ISSUER.href);
    expect(persisted?.clientSecret).toBeUndefined();
    expect(persisted?.tokenEndpointAuthMethod).toBeUndefined();
  });

  it("an OPTION clientSecret with NO confidential method resolves to `none` (the secret is NOT sent)", async () => {
    // The documented gotcha: a secret alone does not make a client confidential. With
    // no method (option/persisted) the resolved method defaults to `none`, so the grant
    // uses `none` and the secret is ignored — never silently sent.
    const store = makeStore();
    await seed(store, { clientId: "server-assigned-dynamic-client-id" }); // no method persisted
    await restoreSession({ store, issuer: ISSUER, clientSecret: "lonely-secret" });
    expect(refreshMock.grantClientAuths[0]).toEqual({ method: "none" });
    const persisted = store.map.get(ISSUER.href);
    expect(persisted?.clientSecret).toBeUndefined();
  });
});

describe("isInvalidGrantError — the dead-vs-transient classifier (security-critical)", () => {
  it("true only for a definitive invalid_grant (top-level or nested)", () => {
    expect(isInvalidGrantError({ error: "invalid_grant" })).toBe(true);
    expect(
      isInvalidGrantError({
        cause: { parameters: new URLSearchParams({ error: "invalid_grant" }) },
      }),
    ).toBe(true);
  });
  it("false for transient / other errors (so a blip never wipes a valid token)", () => {
    expect(isInvalidGrantError(new Error("network timeout"))).toBe(false);
    expect(isInvalidGrantError({ error: "invalid_client" })).toBe(false);
    expect(isInvalidGrantError({ error: "temporarily_unavailable" })).toBe(false);
    expect(isInvalidGrantError(undefined)).toBe(false);
    expect(isInvalidGrantError(null)).toBe(false);
    expect(isInvalidGrantError("invalid_grant")).toBe(false); // a bare string is not the shape
    expect(isInvalidGrantError({ cause: { parameters: "not-a-URLSearchParams" } })).toBe(false);
  });
});

describe("forgetPersisted / clearPersisted — logout drops the durable credential", () => {
  it("forgetPersisted drops the persisted refresh token + key for the issuer", async () => {
    const store = makeStore();
    await seed(store);
    expect(store.map.has(ISSUER.href)).toBe(true);
    await forgetPersisted(store, ISSUER);
    expect(store.map.has(ISSUER.href)).toBe(false);
  });

  it("clearPersisted is idempotent + swallows a throwing delete", async () => {
    const throwingStore: SessionStore = {
      get: async () => undefined,
      put: async () => {},
      delete: async () => {
        throw new Error("delete failed");
      },
    };
    await expect(clearPersisted(throwingStore, ISSUER)).resolves.toBeUndefined();
  });
});

describe("hasPersisted — tri-state lets the caller keep the pointer under uncertainty", () => {
  it("'present' when a credential exists, 'absent' when none", async () => {
    const store = makeStore();
    expect(await hasPersisted(store, ISSUER)).toBe("absent"); // empty store
    await seed(store);
    expect(await hasPersisted(store, ISSUER)).toBe("present");
  });

  it("'present' after a transient restore failure preserved the credential, 'absent' after a dead-token clear", async () => {
    const store = makeStore();
    await seed(store);

    // Transient failure — restoreSession preserves the credential.
    refreshMock.reject = new Error("network timeout");
    expect(await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS })).toBeUndefined();
    expect(await hasPersisted(store, ISSUER)).toBe("present"); // KEEP the pointer

    // Now a definitive invalid_grant clears the credential.
    refreshMock.reject = Object.assign(new Error("invalid_grant"), { error: "invalid_grant" });
    expect(await restoreSession({ store, issuer: ISSUER, ...CLIENT_OPTS })).toBeUndefined();
    expect(await hasPersisted(store, ISSUER)).toBe("absent"); // clear the pointer
  });

  it("'unknown' when the store read throws (do NOT treat as absent → keep pointer)", async () => {
    const throwingStore: SessionStore = {
      get: async () => {
        throw new Error("IndexedDB read failed");
      },
      put: async () => {},
      delete: async () => {},
    };
    expect(await hasPersisted(throwingStore, ISSUER)).toBe("unknown");
  });
});

describe("WebID scoping — account A's persisted token never restores account B", () => {
  it("a restore for B's issuer rebuilds B's session, leaving A's persisted entry untouched", async () => {
    const store = makeStore();
    const issuerB = new URL("https://issuer-b.example/");
    const keyA = await sampleKey();
    const keyB = await sampleKey();
    // Two accounts, each under its OWN issuer key.
    store.map.set(ISSUER.href, {
      issuer: ISSUER.href,
      webId: WEBID_A,
      refreshToken: "rt-A",
      dpopKey: keyA,
    });
    store.map.set(issuerB.href, {
      issuer: issuerB.href,
      webId: WEBID_B,
      refreshToken: "rt-B",
      dpopKey: keyB,
    });

    // Restoring B's issuer authenticates AS B (the id_token claims read authState).
    authState.webId = WEBID_B;
    const restored = await restoreSession({ store, issuer: issuerB, ...CLIENT_OPTS });
    expect(restored?.webId).toBe(WEBID_B);
    expect(restored?.webId).not.toBe(WEBID_A);
    // B's grant redeemed B's token only.
    expect(refreshMock.grantTokens).toEqual(["rt-B"]);
    // A's persisted credential (under A's issuer key) is wholly untouched.
    expect(store.map.get(ISSUER.href)?.webId).toBe(WEBID_A);
    expect(store.map.get(ISSUER.href)?.refreshToken).toBe("rt-A");
  });
});
