// ─── IP Blocker ───────────────────────────────────────────────────────────────
// Manages temporary and permanent IP bans.
// In-memory store — swap for Redis in production for cluster-wide enforcement.

// ── Types ──────────────────────────────────────────────────────────────────────

export type BlockReason =
  "brute_force" | "fraud_suspected" | "scraping" | "spam" | "manual_block";

export interface BlockRecord {
  ip: string;
  reason: BlockReason;
  blockedAt: Date;
  expiresAt: Date | null; // null = permanent
  hitCount: number;
}

// ── Store ─────────────────────────────────────────────────────────────────────

const blocklist = new Map<string, BlockRecord>();

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Block an IP address.
 * @param durationMs  Block duration in milliseconds. Omit or pass null for permanent.
 */
export function blockIP(
  ip: string,
  reason: BlockReason,
  durationMs?: number | null,
): BlockRecord {
  const now = new Date();
  const record: BlockRecord = {
    ip,
    reason,
    blockedAt: now,
    expiresAt: durationMs != null ? new Date(now.getTime() + durationMs) : null,
    hitCount: 0,
  };
  blocklist.set(ip, record);
  return record;
}

/**
 * Check whether an IP is currently blocked.
 * Automatically removes expired entries.
 */
export function isIPBlocked(ip: string): {
  blocked: boolean;
  record?: BlockRecord;
} {
  const record = blocklist.get(ip);
  if (!record) return { blocked: false };

  if (record.expiresAt !== null && record.expiresAt < new Date()) {
    blocklist.delete(ip);
    return { blocked: false };
  }

  // Increment hit counter so we can track how often blocked IPs retry
  record.hitCount += 1;
  return { blocked: true, record };
}

/** Remove a specific IP from the blocklist. */
export function unblockIP(ip: string): boolean {
  return blocklist.delete(ip);
}

/** Return all currently active block records. */
export function listBlockedIPs(): BlockRecord[] {
  const now = new Date();
  const active: BlockRecord[] = [];
  for (const [ip, record] of blocklist) {
    if (record.expiresAt === null || record.expiresAt >= now) {
      active.push(record);
    } else {
      blocklist.delete(ip);
    }
  }
  return active;
}

/**
 * Auto-escalating IP block: temp block → permanent after threshold.
 * Call this on each suspicious event from an IP.
 */
export function escalateIPBlock(
  ip: string,
  reason: BlockReason,
  strikeThreshold = 3,
): BlockRecord {
  const existing = blocklist.get(ip);
  if (existing && existing.hitCount >= strikeThreshold) {
    return blockIP(ip, reason, null); // escalate to permanent
  }
  // Temporary: 1 hour
  const record = blockIP(ip, reason, 60 * 60 * 1000);
  if (existing) {
    record.hitCount = existing.hitCount + 1;
  }
  return record;
}

/**
 * Parse the real client IP from common proxy headers.
 * Always call this instead of reading req.ip directly.
 */
export function extractClientIP(
  remoteAddress: string | undefined,
  xForwardedFor: string | string[] | undefined,
): string {
  if (xForwardedFor) {
    const header = Array.isArray(xForwardedFor)
      ? xForwardedFor[0]
      : xForwardedFor;
    const first = header.split(",")[0]?.trim();
    if (first) return first;
  }
  return remoteAddress ?? "unknown";
}

