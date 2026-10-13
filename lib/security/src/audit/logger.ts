// ─── Audit Logger ─────────────────────────────────────────────────────────────
// Structured, append-only audit log for sensitive platform events.
// Emits to stdout (captured by your log aggregator) and in-memory buffer.
// In production: pipe stdout to your SIEM / secure log store.

// ── Types ──────────────────────────────────────────────────────────────────────

export type AuditCategory =
  "auth" | "payment" | "admin" | "data" | "security" | "booking";

export type AuditSeverity = "info" | "warn" | "critical";

export interface AuditEntry {
  id: string;
  timestamp: string; // ISO 8601
  category: AuditCategory;
  severity: AuditSeverity;
  action: string; // e.g. "user.login.failed"
  actorId: string | null;
  actorRole?: string;
  targetId?: string;
  targetType?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
  outcome: "success" | "failure" | "blocked";
}

// ── In-memory ring buffer (recent entries) ─────────────────────────────────────

const BUFFER_SIZE = 1000;
const buffer: AuditEntry[] = [];

// ── Core writer ───────────────────────────────────────────────────────────────

import { randomUUID } from "node:crypto";

function write(entry: Omit<AuditEntry, "id" | "timestamp">): AuditEntry {
  const full: AuditEntry = {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    ...entry,
  };

  // Structured JSON to stdout — captured by your log aggregator
  process.stdout.write(JSON.stringify({ audit: full }) + "\n");

  // Keep the last N entries in memory for the admin dashboard
  buffer.push(full);
  if (buffer.length > BUFFER_SIZE) {
    buffer.shift();
  }

  return full;
}

// ── Public logging helpers ────────────────────────────────────────────────────

export function logUserAction(params: {
  action: string;
  actorId: string;
  actorRole?: string;
  ipAddress?: string;
  userAgent?: string;
  outcome?: AuditEntry["outcome"];
  metadata?: Record<string, unknown>;
}): AuditEntry {
  return write({
    category: "auth",
    severity: "info",
    outcome: "success",
    targetId: undefined,
    ...params,
  });
}

export function logAdminAction(params: {
  action: string;
  actorId: string;
  targetId?: string;
  targetType?: string;
  ipAddress?: string;
  outcome?: AuditEntry["outcome"];
  metadata?: Record<string, unknown>;
}): AuditEntry {
  return write({
    category: "admin",
    severity: "warn",
    outcome: "success",
    actorRole: "admin-web",
    ...params,
  });
}

export function logPaymentEvent(params: {
  action: string;
  actorId: string;
  targetId?: string;
  ipAddress?: string;
  outcome: AuditEntry["outcome"];
  metadata?: Record<string, unknown>;
}): AuditEntry {
  return write({
    category: "payment",
    severity: params.outcome === "failure" ? "warn" : "info",
    ...params,
  });
}

export function logSecurityEvent(params: {
  action: string;
  actorId: string | null;
  severity?: AuditSeverity;
  ipAddress?: string;
  outcome: AuditEntry["outcome"];
  metadata?: Record<string, unknown>;
}): AuditEntry {
  return write({
    category: "security",
    severity: params.severity ?? "warn",
    ...params,
  });
}

// ── Query helpers ─────────────────────────────────────────────────────────────

export function getRecentAuditEntries(limit = 100): AuditEntry[] {
  return buffer.slice(-limit);
}

export function queryAuditEntries(filters: {
  category?: AuditCategory;
  actorId?: string;
  outcome?: AuditEntry["outcome"];
  since?: Date;
}): AuditEntry[] {
  return buffer.filter((entry) => {
    if (filters.category && entry.category !== filters.category) return false;
    if (filters.actorId && entry.actorId !== filters.actorId) return false;
    if (filters.outcome && entry.outcome !== filters.outcome) return false;
    if (filters.since && new Date(entry.timestamp) < filters.since)
      return false;
    return true;
  });
}
