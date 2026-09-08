/**
 * Issue #16 — Handle SEP-10 token expiration and refresh gracefully.
 *
 * The auth middleware (src/plugins/auth.ts) classifies bearer-token failures
 * instead of collapsing them into one generic 401:
 *
 *  - expired (or inside the near-expiry margin) → TOKEN_EXPIRED, with a hint
 *    to re-authenticate via SEP-10;
 *  - malformed / wrong signature / wrong issuer / wrong audience / wrong
 *    algorithm / not-yet-valid / missing claims → INVALID_TOKEN;
 *  - no Authorization header, or a non-Bearer scheme → UNAUTHORIZED;
 *  - a valid token proceeds normally.
 *
 * Both layers are covered: `verifyToken` directly, and the full request path
 * through `app.inject` against `/me`, so the codes the client actually
 * receives are what is asserted here.
 */
import { describe, it, expect, beforeAll, vi } from "vitest";
import jwt from "jsonwebtoken";
import { Keypair } from "@stellar/stellar-sdk";

vi.mock("../../src/db", () => ({
  prisma: {
    user: { findUnique: vi.fn(), upsert: vi.fn() },
    group: { findUnique: vi.fn() },
    groupMember: { findUnique: vi.fn() },
    idempotencyKey: { findUnique: vi.fn(), create: vi.fn() },
    auditLog: { create: vi.fn() },
    $disconnect: vi.fn(),
  },
}));

vi.mock("../../src/services/stellar", async (importActual) => {
  const actual = await importActual<typeof import("../../src/services/stellar")>();
  return {
    ...actual,
    stellar: {
      ...actual.stellar,
      loadAccount: vi.fn(async () => ({
        exists: false,
        sequence: "0",
        balances: [],
        signers: [],
        thresholds: { low: 0, med: 0, high: 0 },
      })),
    },
  };
});

import { buildApp } from "../../src/app";
import { signToken, verifyToken } from "../../src/plugins/auth";
import { config } from "../../src/config";
import { AppError, ErrorCode } from "../../src/lib/errors";

const PUBLIC_KEY = Keypair.random().publicKey();
const USER = { id: "user_1", stellarPublicKey: PUBLIC_KEY };

/** Sign a session token with explicit claims, bypassing signToken's TTL. */
function signWith(overrides: jwt.SignOptions = {}, secret = config.JWT_SECRET): string {
  return jwt.sign({ sub: USER.id, pk: USER.stellarPublicKey }, secret, {
    algorithm: "HS256",
    issuer: config.JWT_ISSUER,
    audience: config.JWT_AUDIENCE,
    ...overrides,
  });
}

let app: Awaited<ReturnType<typeof buildApp>>;

beforeAll(async () => {
  app = await buildApp();
});

describe("verifyToken classification (unit)", () => {
  it("returns the account for a valid token", () => {
    expect(verifyToken(signToken(USER))).toEqual(USER);
  });

  it("throws TOKEN_EXPIRED for a token whose exp has passed", () => {
    const token = signWith({ expiresIn: -60 });
    try {
      verifyToken(token);
      expect.unreachable("verifyToken should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AppError);
      expect((err as AppError).status).toBe(401);
      expect((err as AppError).code).toBe(ErrorCode.TOKEN_EXPIRED);
    }
  });

  it("throws TOKEN_EXPIRED for a token inside the near-expiry margin", () => {
    // Default margin is 30s; a 5s lifetime is inside it even though the jwt
    // library itself would still accept the signature.
    const token = signWith({ expiresIn: 5 });
    try {
      verifyToken(token);
      expect.unreachable("verifyToken should have thrown");
    } catch (err) {
      expect((err as AppError).code).toBe(ErrorCode.TOKEN_EXPIRED);
    }
  });

  it("throws INVALID_TOKEN for a token signed with the wrong secret", () => {
    const token = signWith({ expiresIn: "1h" }, "a-completely-different-secret");
    try {
      verifyToken(token);
      expect.unreachable("verifyToken should have thrown");
    } catch (err) {
      expect((err as AppError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("throws INVALID_TOKEN for a malformed envelope", () => {
    try {
      verifyToken("not-a-jwt");
      expect.unreachable("verifyToken should have thrown");
    } catch (err) {
      expect((err as AppError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("throws INVALID_TOKEN for a token with the wrong issuer", () => {
    const token = jwt.sign({ sub: USER.id, pk: USER.stellarPublicKey }, config.JWT_SECRET, {
      algorithm: "HS256",
      issuer: "some-other-issuer",
      audience: config.JWT_AUDIENCE,
      expiresIn: "1h",
    });
    expect(() => verifyToken(token)).toThrow(
      expect.objectContaining({ code: ErrorCode.INVALID_TOKEN })
    );
  });

  it("throws INVALID_TOKEN for a token with the wrong audience", () => {
    const token = jwt.sign({ sub: USER.id, pk: USER.stellarPublicKey }, config.JWT_SECRET, {
      algorithm: "HS256",
      issuer: config.JWT_ISSUER,
      audience: "some-other-audience",
      expiresIn: "1h",
    });
    expect(() => verifyToken(token)).toThrow(
      expect.objectContaining({ code: ErrorCode.INVALID_TOKEN })
    );
  });

  it("throws INVALID_TOKEN for a token with no exp claim", () => {
    const token = signWith(); // no expiresIn → no exp
    expect(() => verifyToken(token)).toThrow(
      expect.objectContaining({ code: ErrorCode.INVALID_TOKEN })
    );
  });

  it("throws INVALID_TOKEN for a token missing the account claims", () => {
    const token = jwt.sign({ sub: USER.id }, config.JWT_SECRET, {
      algorithm: "HS256",
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
      expiresIn: "1h",
    });
    expect(() => verifyToken(token)).toThrow(
      expect.objectContaining({ code: ErrorCode.INVALID_TOKEN })
    );
  });

  it("never echoes the jwt library's message", () => {
    // jsonwebtoken's errors quote token fragments; the AppError must not.
    try {
      verifyToken("garbage.token.input");
    } catch (err) {
      expect((err as AppError).message).not.toContain("garbage.token.input");
    }
  });
});

describe("auth middleware over HTTP (GET /me)", () => {
  it("valid token proceeds normally", async () => {
    const { prisma } = (await import("../../src/db")) as any;
    prisma.user.findUnique.mockResolvedValueOnce({
      id: USER.id,
      stellarPublicKey: USER.stellarPublicKey,
      displayName: "Tester",
      avatarUrl: null,
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });

    const res = await app.inject({
      method: "GET",
      url: "/me",
      headers: { authorization: `Bearer ${signToken(USER)}` },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().user.id).toBe(USER.id);
  });

  it("expired token returns 401 TOKEN_EXPIRED with the SEP-10 re-authentication hint", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/me",
      headers: { authorization: `Bearer ${signWith({ expiresIn: -60 })}` },
    });

    expect(res.statusCode).toBe(401);
    const body = res.json();
    expect(body.error).toBe("TOKEN_EXPIRED");
    expect(body.code).toBe("TOKEN_EXPIRED");
    expect(body.message).toBe("Token expired");
    expect(body.requestId).toBeTruthy();
    expect(body.details).toMatchObject({ reauthenticate: "sep10" });
    expect(body.details.hint).toContain("SEP-10");
  });

  it("near-expiry token returns 401 TOKEN_EXPIRED", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/me",
      headers: { authorization: `Bearer ${signWith({ expiresIn: 5 })}` },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe("TOKEN_EXPIRED");
  });

  it("token signed with the wrong secret returns 401 INVALID_TOKEN", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/me",
      headers: {
        authorization: `Bearer ${signWith({ expiresIn: "1h" }, "a-completely-different-secret")}`,
      },
    });

    expect(res.statusCode).toBe(401);
    const body = res.json();
    expect(body.error).toBe("INVALID_TOKEN");
    expect(body.code).toBe("INVALID_TOKEN");
    expect(body.message).toBe("Invalid token");
    expect(body.requestId).toBeTruthy();
  });

  it("malformed token returns 401 INVALID_TOKEN", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/me",
      headers: { authorization: "Bearer not-a-jwt" },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe("INVALID_TOKEN");
  });

  it("token with wrong issuer returns 401 INVALID_TOKEN", async () => {
    const token = jwt.sign({ sub: USER.id, pk: USER.stellarPublicKey }, config.JWT_SECRET, {
      algorithm: "HS256",
      issuer: "some-other-issuer",
      audience: config.JWT_AUDIENCE,
      expiresIn: "1h",
    });
    const res = await app.inject({
      method: "GET",
      url: "/me",
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe("INVALID_TOKEN");
  });

  it("token with wrong algorithm returns 401 INVALID_TOKEN", async () => {
    // Header claims "none" — must never be accepted.
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({
        sub: USER.id,
        pk: USER.stellarPublicKey,
        iss: config.JWT_ISSUER,
        aud: config.JWT_AUDIENCE,
        exp: Math.floor(Date.now() / 1000) + 3600,
      })
    ).toString("base64url");
    const res = await app.inject({
      method: "GET",
      url: "/me",
      headers: { authorization: `Bearer ${header}.${payload}.` },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe("INVALID_TOKEN");
  });

  it("missing Authorization header returns 401 UNAUTHORIZED", async () => {
    const res = await app.inject({ method: "GET", url: "/me" });

    expect(res.statusCode).toBe(401);
    const body = res.json();
    expect(body.code).toBe("UNAUTHORIZED");
    expect(body.requestId).toBeTruthy();
  });

  it("non-Bearer scheme returns 401 UNAUTHORIZED", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/me",
      headers: { authorization: "Token xxx" },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().code).toBe("UNAUTHORIZED");
  });

  it("every 401 keeps the standard error envelope shape", async () => {
    const cases = [
      { authorization: `Bearer ${signWith({ expiresIn: -60 })}` }, // expired
      { authorization: "Bearer not-a-jwt" }, // malformed
      { authorization: `Bearer ${signWith({ expiresIn: "1h" }, "wrong-secret-wrong-secret")}` }, // bad signature
    ];

    for (const headers of cases) {
      const res = await app.inject({ method: "GET", url: "/me", headers });
      const body = res.json();
      expect(res.statusCode).toBe(401);
      expect(typeof body.code).toBe("string");
      expect(body.code).toBe(body.error);
      expect(typeof body.message).toBe("string");
      expect(typeof body.requestId).toBe("string");
      expect(body).not.toHaveProperty("stack");
      expect(body).not.toHaveProperty("statusCode");
    }
  });
});
