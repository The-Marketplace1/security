// ─── Audit Service ────────────────────────────────────────────────────────────
// Higher-level audit helpers that bundle common event patterns so callers
// don't have to assemble audit entries manually.

import {
  logUserAction,
  logAdminAction,
  logPaymentEvent,
  logSecurityEvent,
  type AuditEntry,
} from "./logger.js";

// ── Auth events ───────────────────────────────────────────────────────────────

export function auditLoginAttempt(params: {
  userId: string | null;
  email: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  reason?: string;
}): AuditEntry {
  if (params.userId) {
    return logUserAction({
      action: params.success ? "auth.login.success" : "auth.login.failed",
      actorId: params.userId,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      outcome: params.success ? "success" : "failure",
      metadata: { email: params.email, reason: params.reason },
    });
  }
  return logSecurityEvent({
    action: "auth.login.unknown_user",
    actorId: null,
    ipAddress: params.ipAddress,
    outcome: "failure",
    metadata: { email: params.email, reason: params.reason },
  });
}

export function auditLogout(params: {
  userId: string;
  sessionId: string;
  ipAddress: string;
}): AuditEntry {
  return logUserAction({
    action: "auth.logout",
    actorId: params.userId,
    ipAddress: params.ipAddress,
    outcome: "success",
    metadata: { sessionId: params.sessionId },
  });
}

export function auditPasswordChange(params: {
  userId: string;
  ipAddress: string;
  forced?: boolean;
}): AuditEntry {
  return logUserAction({
    action: "auth.password.changed",
    actorId: params.userId,
    ipAddress: params.ipAddress,
    outcome: "success",
    metadata: { forced: params.forced ?? false },
  });
}

export function auditAccountLocked(params: {
  userId: string;
  ipAddress: string;
  reason: string;
}): AuditEntry {
  return logSecurityEvent({
    action: "auth.account.locked",
    actorId: params.userId,
    severity: "warn",
    ipAddress: params.ipAddress,
    outcome: "blocked",
    metadata: { reason: params.reason },
  });
}

// ── Payment events ────────────────────────────────────────────────────────────

export function auditPaymentAttempt(params: {
  userId: string;
  paymentId: string;
  amountCents: number;
  currency: string;
  success: boolean;
  fraudSignals?: string[];
  ipAddress: string;
}): AuditEntry {
  return logPaymentEvent({
    action: params.success ? "payment.charge.success" : "payment.charge.failed",
    actorId: params.userId,
    targetId: params.paymentId,
    ipAddress: params.ipAddress,
    outcome: params.success ? "success" : "failure",
    metadata: {
      amountCents: params.amountCents,
      currency: params.currency,
      fraudSignals: params.fraudSignals,
    },
  });
}

export function auditPaymentBlocked(params: {
  userId: string;
  paymentId: string;
  signals: string[];
  riskScore: number;
  ipAddress: string;
}): AuditEntry {
  return logPaymentEvent({
    action: "payment.blocked.fraud",
    actorId: params.userId,
    targetId: params.paymentId,
    ipAddress: params.ipAddress,
    outcome: "blocked",
    metadata: { signals: params.signals, riskScore: params.riskScore },
  });
}

// ── Admin events ──────────────────────────────────────────────────────────────

export function auditAdminUserUpdate(params: {
  adminId: string;
  targetUserId: string;
  changes: Record<string, unknown>;
  ipAddress: string;
}): AuditEntry {
  return logAdminAction({
    action: "admin.user.updated",
    actorId: params.adminId,
    targetId: params.targetUserId,
    targetType: "user",
    ipAddress: params.ipAddress,
    outcome: "success",
    metadata: { changes: params.changes },
  });
}

export function auditAdminIPBlock(params: {
  adminId: string;
  ip: string;
  reason: string;
}): AuditEntry {
  return logAdminAction({
    action: "admin.ip.blocked",
    actorId: params.adminId,
    targetId: params.ip,
    targetType: "ip_address",
    outcome: "success",
    metadata: { reason: params.reason },
  });
}

// ── Security events ───────────────────────────────────────────────────────────

export function auditSuspiciousActivity(params: {
  userId: string | null;
  activity: string;
  ipAddress: string;
  metadata?: Record<string, unknown>;
}): AuditEntry {
  return logSecurityEvent({
    action: `security.suspicious.${params.activity}`,
    actorId: params.userId,
    severity: "warn",
    ipAddress: params.ipAddress,
    outcome: "blocked",
    metadata: params.metadata,
  });
}
