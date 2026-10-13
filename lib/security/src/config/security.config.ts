// ─── Security Configuration ───────────────────────────────────────────────────
// Central config for all security modules. Values are read from environment
// variables with safe defaults for development.

export interface SecurityConfig {
  /** Secret used to sign/verify JWT access tokens */
  jwtSecret: string;
  /** Secret used to sign/verify JWT refresh tokens */
  jwtRefreshSecret: string;
  /** Access token lifetime in seconds (default 15 min) */
  jwtExpiresInSeconds: number;
  /** Refresh token lifetime in seconds (default 7 days) */
  jwtRefreshExpiresInSeconds: number;
  /** AES-256-GCM encryption key, 32 bytes hex-encoded */
  encryptionKey: string;
  /** Max login attempts before lockout */
  maxLoginAttempts: number;
  /** Lockout duration in seconds after brute-force detected */
  lockoutDurationSeconds: number;
  /** Max API requests per window per IP */
  rateLimitMax: number;
  /** Rate limit window in milliseconds */
  rateLimitWindowMs: number;
}

function requireEnv(key: string, fallback?: string): string {
  const value = process.env[key] ?? fallback;
  if (!value) {
    throw new Error(
      `[security] Required environment variable "${key}" is not set.`,
    );
  }
  return value;
}

export function loadSecurityConfig(): SecurityConfig {
  return {
    jwtSecret: requireEnv("JWT_SECRET", "dev-jwt-secret-change-in-production"),
    jwtRefreshSecret: requireEnv(
      "JWT_REFRESH_SECRET",
      "dev-refresh-secret-change-in-production",
    ),
    jwtExpiresInSeconds: parseInt(
      process.env["JWT_EXPIRES_IN_SECONDS"] ?? "900",
      10,
    ),
    jwtRefreshExpiresInSeconds: parseInt(
      process.env["JWT_REFRESH_EXPIRES_IN_SECONDS"] ?? "604800",
      10,
    ),
    encryptionKey: requireEnv(
      "ENCRYPTION_KEY",
      // 32-byte hex key for dev only — NEVER use in production
      "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    maxLoginAttempts: parseInt(process.env["MAX_LOGIN_ATTEMPTS"] ?? "5", 10),
    lockoutDurationSeconds: parseInt(
      process.env["LOCKOUT_DURATION_SECONDS"] ?? "900",
      10,
    ),
    rateLimitMax: parseInt(process.env["RATE_LIMIT_MAX"] ?? "100", 10),
    rateLimitWindowMs: parseInt(
      process.env["RATE_LIMIT_WINDOW_MS"] ?? "60000",
      10,
    ),
  };
}

export const securityConfig = loadSecurityConfig();
