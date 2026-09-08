import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import fp from "fastify-plugin";
import jwt, { JsonWebTokenError, NotBeforeError, TokenExpiredError } from "jsonwebtoken";
import { z } from "zod";
import { config } from "../config";
import { Errors } from "../errors";

/**
 * Minimum remaining lifetime (seconds) a JWT must have when presented.
 * Tokens whose `exp` claim is closer than this margin to the current clock
 * are rejected as near-expired.
 */
const TOKEN_EXPIRY_MARGIN_SECONDS = config.TOKEN_EXPIRY_MARGIN_SECONDS ?? 30;

export interface AuthUser {
  id: string;
  stellarPublicKey: string;
}

declare module "fastify" {
  interface FastifyRequest {
    user?: AuthUser;
  }
  interface FastifyInstance {
    authenticate: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
}

const JWT_ALGORITHM = "HS256" as const;

export function signToken(user: AuthUser): string {
  return jwt.sign(
    { sub: user.id, pk: user.stellarPublicKey },
    config.JWT_SECRET,
    {
      algorithm: JWT_ALGORITHM,
      expiresIn: config.jwtExpiresIn,
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
    }
  );
}

/**
 * Verify a bearer token and return the account it was issued for.
 *
 * Enforces algorithm, issuer, audience, and expiration in addition to the
 * signature so a token minted for a different environment/audience (or
 * signed with a different algorithm) is rejected outright, and validates the
 * claim shape so a malformed/tampered payload can't be coerced into
 * authenticating as an arbitrary account.
 *
 * Failures are classified rather than collapsed: an expired token throws
 * TOKEN_EXPIRED (the client can silently re-authenticate via SEP-10), while
 * every other rejection — malformed envelope, wrong signature, wrong
 * issuer/audience/algorithm, not-yet-valid, missing claims — throws
 * INVALID_TOKEN (the credential is unusable and must be re-obtained by
 * authenticating again). Neither ever echoes the jwt library's own message,
 * which can quote token fragments.
 */
export function verifyToken(token: string): AuthUser {
  let decoded: jwt.JwtPayload;
  try {
    decoded = jwt.verify(token, config.JWT_SECRET, {
      algorithms: [JWT_ALGORITHM],
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
    }) as jwt.JwtPayload;
  } catch (err) {
    // JsonWebTokenError covers both "jwt expired" (thrown as
    // TokenExpiredError, a subclass) and structural/claim failures. The
    // distinct TOKEN_EXPIRED code — not the subclass — is what a client
    // branches on, and it is only emitted for a token whose signature was
    // otherwise proven.
    if (err instanceof TokenExpiredError) {
      throw Errors.tokenExpired();
    }
    if (err instanceof JsonWebTokenError || err instanceof NotBeforeError) {
      throw Errors.invalidToken();
    }
    // Anything else (bad secret shape, non-string token, …) is still a 401,
    // never a 500.
    throw Errors.invalidToken();
  }

  // A session token without an expiry provides no bounded lifetime — every
  // token this API mints carries one — so its absence is a malformed token,
  // not an open-ended session.
  if (typeof decoded.exp !== "number") {
    throw Errors.invalidToken("Invalid token: missing expiry");
  }

  // Reject tokens that are too close to expiry: even though the SDK's own
  // check would still accept them within this margin, a token forged or
  // replayed moments before expiry should never grant a session. An
  // otherwise-authentic token this close to its end is an expiry case, so it
  // maps to TOKEN_EXPIRED rather than INVALID_TOKEN.
  const remainingSeconds = decoded.exp - Math.floor(Date.now() / 1000);
  if (remainingSeconds < TOKEN_EXPIRY_MARGIN_SECONDS) {
    throw Errors.tokenExpired(
      "Token expired (within the near-expiry margin)"
    );
  }

  const { sub, pk } = decoded;
  if (typeof sub !== "string" || !sub || typeof pk !== "string" || !pk) {
    throw Errors.invalidToken("Invalid token: missing required claims");
  }

  return { id: sub, stellarPublicKey: pk };
}

const authorizationHeaderSchema = z
  .string()
  .regex(/^Bearer\s+\S+$/, "Authorization must use the Bearer scheme");

/**
 * The authenticate preHandler.
 *
 * Rejection codes, by case:
 *  - no Authorization header, or a non-Bearer scheme → UNAUTHORIZED
 *    (Authentication required — there is no token to classify);
 *  - a Bearer token that fails verification → TOKEN_EXPIRED or INVALID_TOKEN,
 *    re-thrown as-is so the classified code from verifyToken reaches the
 *    client instead of being masked into a generic 401.
 */
async function authenticate(req: FastifyRequest, _reply: FastifyReply) {
  const parsedHeader = authorizationHeaderSchema.safeParse(req.headers.authorization);
  if (!parsedHeader.success) {
    throw Errors.unauthorized();
  }

  const token = parsedHeader.data.slice("Bearer ".length).trim();
  req.user = verifyToken(token);
}

export default fp(async function authPlugin(app: FastifyInstance) {
  app.decorate("authenticate", authenticate);
});

/** Read the authenticated user or throw 401. */
export function requireUser(req: FastifyRequest): AuthUser {
  if (!req.user) throw Errors.unauthorized();
  return req.user;
}
