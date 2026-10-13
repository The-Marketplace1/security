// ─── Session Guard ────────────────────────────────────────────────────────────
// Tracks active sessions and detects session hijacking / concurrent device abuse.
// In-memory store — swap for Redis in production.

import { randomUUID } from "node:crypto";
import type { UserRole } from "./jwt.validator.js";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface SessionRecord {
  sessionId: string;
  userId: string;
  role: UserRole;
  ipAddress: string;
  userAgent: string;
  createdAt: Date;
  lastSeenAt: Date;
  expiresAt: Date;
}

export interface NewDeviceAlert {
  userId: string;
  sessionId: string;
  ipAddress: string;
  userAgent: string;
  detectedAt: Date;
}

// ── In-memory session store ───────────────────────────────────────────────────

const sessions = new Map<string, SessionRecord>();

// ── Session management ────────────────────────────────────────────────────────

/**
 * Create and register a new session record.
 * Returns the generated session ID.
 */
export function createSession(params: {
  userId: string;
  role: UserRole;
  ipAddress: string;
  userAgent: string;
  ttlSeconds?: number;
}): SessionRecord {
  const sessionId = randomUUID();
  const now = new Date();
  const ttl = params.ttlSeconds ?? 7 * 24 * 3600; // default 7 days
  const record: SessionRecord = {
    sessionId,
    userId: params.userId,
    role: params.role,
    ipAddress: params.ipAddress,
    userAgent: params.userAgent,
    createdAt: now,
    lastSeenAt: now,
    expiresAt: new Date(now.getTime() + ttl * 1000),
  };
  sessions.set(sessionId, record);
  return record;
}

/** Retrieve a session record by ID. Returns undefined if not found or expired. */
export function getSession(sessionId: string): SessionRecord | undefined {
  const record = sessions.get(sessionId);
  if (!record) return undefined;
  if (record.expiresAt < new Date()) {
    sessions.delete(sessionId);
    return undefined;
  }
  return record;
}

/** Refresh the lastSeenAt timestamp — call on every authenticated request. */
export function touchSession(sessionId: string): void {
  const record = sessions.get(sessionId);
  if (record) {
    record.lastSeenAt = new Date();
  }
}

/** Invalidate (destroy) a session — use on logout or hijacking detection. */
export function invalidateSession(sessionId: string): void {
  sessions.delete(sessionId);
}

/** Invalidate ALL sessions for a user — use on password reset or account lock. */
export function invalidateAllUserSessions(userId: string): void {
  for (const [id, record] of sessions) {
    if (record.userId === userId) {
      sessions.delete(id);
    }
  }
}

/** Return all active sessions for a user — useful for the "active devices" view. */
export function listUserSessions(userId: string): SessionRecord[] {
  const now = new Date();
  const result: SessionRecord[] = [];
  for (const record of sessions.values()) {
    if (record.userId === userId && record.expiresAt >= now) {
      result.push(record);
    }
  }
  return result;
}

// ── New-device detection ──────────────────────────────────────────────────────

/**
 * Check whether a request is coming from a device/IP not seen before for this user.
 * Returns an alert object if a new device is detected, null otherwise.
 */
export function detectNewDevice(
  userId: string,
  ipAddress: string,
  userAgent: string,
  sessionId: string,
): NewDeviceAlert | null {
  const existingSessions = listUserSessions(userId);
  const isKnownDevice = existingSessions.some(
    (s) => s.ipAddress === ipAddress && s.userAgent === userAgent,
  );
  if (isKnownDevice) return null;
  return {
    userId,
    sessionId,
    ipAddress,
    userAgent,
    detectedAt: new Date(),
  };
}

// ── Session hijacking detection ───────────────────────────────────────────────

/**
 * Validate that a request's IP/UA matches the stored session.
 * Returns false if the session looks hijacked.
 */
export function validateSessionBinding(
  sessionId: string,
  currentIp: string,
  currentUa: string,
): { valid: boolean; reason?: string } {
  const record = getSession(sessionId);
  if (!record) return { valid: false, reason: "session_not_found" };

  // Allow IP changes (mobile users switch networks) but flag UA changes
  if (record.userAgent && currentUa && record.userAgent !== currentUa) {
    return { valid: false, reason: "user_agent_mismatch" };
  }
  return { valid: true };
}
