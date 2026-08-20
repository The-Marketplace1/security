// ─── Rate Limiter ─────────────────────────────────────────────────────────────
// Token-bucket / sliding-window rate limiter.
// In-memory store — swap the store implementation for Redis in production.

import { securityConfig } from "../config/security.config.js";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface RateLimitOptions {
  /** Identifier for this limit rule (e.g. "login", "api", "otp") */
  key: string;
  /** Max requests allowed in the window */
  max?: number;
  /** Window size in milliseconds */
  windowMs?: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
  retryAfterMs: number;
}

// ── In-memory store ───────────────────────────────────────────────────────────

interface BucketEntry {
  count: number;
  windowStart: number;
}

const store = new Map<string, BucketEntry>();

function getStoreKey(rule: string, identifier: string): string {
  return `${rule}:${identifier}`;
}

// ── Core rate limiter ─────────────────────────────────────────────────────────

/**
 * Check and increment the request count for a given identifier.
 * @param identifier  A per-user or per-IP key, e.g. "user:42" or "ip:1.2.3.4"
 */
export function checkRateLimit(
  identifier: string,
  opts: RateLimitOptions,
): RateLimitResult {
  const max = opts.max ?? securityConfig.rateLimitMax;
  const windowMs = opts.windowMs ?? securityConfig.rateLimitWindowMs;
  const storeKey = getStoreKey(opts.key, identifier);
  const now = Date.now();

  let entry = store.get(storeKey);
  if (!entry || now - entry.windowStart >= windowMs) {
    entry = { count: 0, windowStart: now };
  }

  entry.count += 1;
  store.set(storeKey, entry);

  const windowEnd = entry.windowStart + windowMs;
  const remaining = Math.max(0, max - entry.count);
  const allowed = entry.count <= max;

  return {
    allowed,
    remaining,
    resetAt: new Date(windowEnd),
    retryAfterMs: allowed ? 0 : windowEnd - now,
  };
}

/**
 * Reset the counter for an identifier (e.g. after successful login).
 */
export function resetRateLimit(identifier: string, key: string): void {
  store.delete(getStoreKey(key, identifier));
}

// ── Preset limit rules ────────────────────────────────────────────────────────

/** Brute-force login protection: 5 attempts / 15 min window */
export function checkLoginRateLimit(identifier: string): RateLimitResult {
  return checkRateLimit(identifier, {
    key: "login",
    max: securityConfig.maxLoginAttempts,
    windowMs: securityConfig.lockoutDurationSeconds * 1000,
  });
}

/** OTP / verification code: 3 attempts / 10 min */
export function checkOTPRateLimit(identifier: string): RateLimitResult {
  return checkRateLimit(identifier, {
    key: "otp",
    max: 3,
    windowMs: 10 * 60 * 1000,
  });
}

/** Generic API endpoint: 100 req / 1 min */
export function checkAPIRateLimit(identifier: string): RateLimitResult {
  return checkRateLimit(identifier, {
    key: "api",
    max: securityConfig.rateLimitMax,
    windowMs: securityConfig.rateLimitWindowMs,
  });
}

/** Payment initiation: 10 attempts / 30 min (fraud-aware) */
export function checkPaymentRateLimit(identifier: string): RateLimitResult {
  return checkRateLimit(identifier, {
    key: "payment",
    max: 10,
    windowMs: 30 * 60 * 1000,
  });
}

