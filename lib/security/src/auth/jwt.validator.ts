// ─── JWT Validator ────────────────────────────────────────────────────────────
// Handles access token + refresh token signing, verification, and blacklisting.
// Blacklist is in-memory; swap the store for Redis in production.

import jwt from "jsonwebtoken";
import { securityConfig } from "../config/security.config.js";

// ── Types ──────────────────────────────────────────────────────────────────────

export type UserRole = "customer" | "professional" | "admin-web";

export interface JWTPayload {
  sub: string; // user ID
  email: string;
  role: UserRole;
  sessionId: string;
  iat?: number;
  exp?: number;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export type JWTValidationResult =
  | { valid: true; payload: JWTPayload }
  | {
      valid: false;
      reason: "expired" | "blacklisted" | "invalid" | "malformed";
    };

// ── Blacklist (in-memory — replace with Redis in production) ──────────────────

const blacklist = new Set<string>();

/**
 * Add a token's jti (or the token itself) to the blacklist.
 * In production, persist this in Redis with a TTL matching the token expiry.
 */
export function blacklistToken(token: string): void {
  blacklist.add(token);
}

export function isBlacklisted(token: string): boolean {
  return blacklist.has(token);
}

// ── Token generation ──────────────────────────────────────────────────────────

import { randomUUID } from "node:crypto";

export function signAccessToken(
  payload: Omit<JWTPayload, "iat" | "exp">,
): string {
  return jwt.sign(payload, securityConfig.jwtSecret, {
    expiresIn: securityConfig.jwtExpiresInSeconds,
    algorithm: "HS256",
  });
}

export function signRefreshToken(
  payload: Pick<JWTPayload, "sub" | "sessionId">,
): string {
  return jwt.sign(payload, securityConfig.jwtRefreshSecret, {
    expiresIn: securityConfig.jwtRefreshExpiresInSeconds,
    algorithm: "HS256",
  });
}

export function issueTokenPair(
  payload: Omit<JWTPayload, "iat" | "exp">,
): TokenPair {
  const sessionId = payload.sessionId ?? randomUUID();
  const accessToken = signAccessToken({ ...payload, sessionId });
  const refreshToken = signRefreshToken({ sub: payload.sub, sessionId });
  return {
    accessToken,
    refreshToken,
    expiresIn: securityConfig.jwtExpiresInSeconds,
  };
}

// ── Token verification ────────────────────────────────────────────────────────

export function verifyAccessToken(token: string): JWTValidationResult {
  if (isBlacklisted(token)) {
    return { valid: false, reason: "blacklisted" };
  }
  try {
    const payload = jwt.verify(token, securityConfig.jwtSecret, {
      algorithms: ["HS256"],
    }) as JWTPayload;
    return { valid: true, payload };
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return { valid: false, reason: "expired" };
    }
    if (err instanceof jwt.JsonWebTokenError) {
      return { valid: false, reason: "invalid" };
    }
    return { valid: false, reason: "malformed" };
  }
}

export function verifyRefreshToken(
  token: string,
):
  | { valid: true; sub: string; sessionId: string }
  | { valid: false; reason: string } {
  if (isBlacklisted(token)) {
    return { valid: false, reason: "blacklisted" };
  }
  try {
    const payload = jwt.verify(token, securityConfig.jwtRefreshSecret, {
      algorithms: ["HS256"],
    }) as Pick<JWTPayload, "sub" | "sessionId">;
    return { valid: true, sub: payload.sub, sessionId: payload.sessionId };
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return { valid: false, reason: "expired" };
    }
    return { valid: false, reason: "invalid" };
  }
}

/**
 * Rotate a refresh token: blacklist the old one, issue a new pair.
 * Always call this on refresh — do NOT reuse refresh tokens.
 */
export function rotateRefreshToken(
  oldRefreshToken: string,
  fullPayload: Omit<JWTPayload, "iat" | "exp">,
): TokenPair | null {
  const result = verifyRefreshToken(oldRefreshToken);
  if (!result.valid) return null;
  blacklistToken(oldRefreshToken);
  return issueTokenPair({ ...fullPayload, sessionId: result.sessionId });

