// ─── @workspace/security ─────────────────────────────────────────────────────
// Production-grade security library for the Marketplace platform.
//
// Modules:
//   auth/        — JWT signing/verification, session management
//   rate-limit/  — Per-IP and per-user rate limiting, IP blocking
//   fraud/       — Payment and booking anomaly detection
//   audit/       — Structured audit logging
//   encryption/  — AES-256-GCM encryption, scrypt password hashing
//   rbac/        — Role-based access control
//   middleware/  — Express middleware stack
//   config/      — Centralised security configuration

// Config
export {
  securityConfig,
  loadSecurityConfig,
} from "./config/security.config.js";
export type { SecurityConfig } from "./config/security.config.js";

// Auth — JWT
export {
  verifyAccessToken,
  verifyRefreshToken,
  signAccessToken,
  signRefreshToken,
  issueTokenPair,
  rotateRefreshToken,
  blacklistToken,
  isBlacklisted,
} from "./auth/jwt.validator.js";
export type {
  JWTPayload,
  JWTValidationResult,
  TokenPair,
  UserRole,
} from "./auth/jwt.validator.js";

// Auth — Session
export {
  createSession,
  getSession,
  touchSession,
  invalidateSession,
  invalidateAllUserSessions,
  listUserSessions,
  detectNewDevice,
  validateSessionBinding,
} from "./auth/session.guard.js";
export type { SessionRecord, NewDeviceAlert } from "./auth/session.guard.js";

// Rate limiting
export {
  checkRateLimit,
  resetRateLimit,
  checkLoginRateLimit,
  checkOTPRateLimit,
  checkAPIRateLimit,
  checkPaymentRateLimit,
} from "./rate-limit/rate.limiter.js";
export type {
  RateLimitOptions,
  RateLimitResult,
} from "./rate-limit/rate.limiter.js";

// IP blocking
export {
  blockIP,
  isIPBlocked,
  unblockIP,
  listBlockedIPs,
  escalateIPBlock,
  extractClientIP,
} from "./rate-limit/ip.blocker.js";
export type { BlockRecord, BlockReason } from "./rate-limit/ip.blocker.js";

// Fraud detection — payments
export {
  isDuplicatePayment,
  markPaymentProcessed,
  assessPaymentFraud,
  recordFailedCardAttempt,
  clearFailedCardAttempts,
} from "./fraud/payment.anomaly.js";
export type {
  PaymentEvent,
  FraudSignal,
  FraudAssessment,
} from "./fraud/payment.anomaly.js";

// Fraud detection — bookings
export {
  assessBookingRisk,
  recordCancellation,
  clearCancellations,
} from "./fraud/booking.anomaly.js";
export type {
  BookingEvent,
  BookingSignal,
  BookingRiskAssessment,
} from "./fraud/booking.anomaly.js";

// Audit logging
export {
  logUserAction,
  logAdminAction,
  logPaymentEvent,
  logSecurityEvent,
  getRecentAuditEntries,
  queryAuditEntries,
} from "./audit/logger.js";
export type {
  AuditEntry,
  AuditCategory,
  AuditSeverity,
} from "./audit/logger.js";

// Audit service (higher-level helpers)
export {
  auditLoginAttempt,
  auditLogout,
  auditPasswordChange,
  auditAccountLocked,
  auditPaymentAttempt,
  auditPaymentBlocked,
  auditAdminUserUpdate,
  auditAdminIPBlock,
  auditSuspiciousActivity,
} from "./audit/audit.service.js";

// Encryption & password hashing
export {
  encryptSensitiveData,
  decryptData,
  hashPassword,
  verifyPassword,
  generateSecureToken,
  generateOTP,
  sha256,
  secureKeyManagement,
} from "./encryption/crypto.service.js";
export type { EncryptedPayload } from "./encryption/crypto.service.js";

// RBAC
export {
  hasPermission,
  assertPermission,
  getPermissions,
  canAccessResource,
  RBACError,
} from "./rbac/rbac.js";
export type { Permission } from "./rbac/rbac.js";

// Express middleware
export {
  ipExtractor,
  ipBlockGuard,
  apiRateLimiter,
  requireAuth,
  requirePermission,
  requireRole,
  securityHeaders,
  inputSanitizer,
  buildCORSOptions,
  applySecurityMiddleware,
} from "./middleware/security.middleware.js";
export type { CORSOptions } from "./middleware/security.middleware.js";

