// ─── Security Middleware ──────────────────────────────────────────────────────
// Express middleware stack that plugs the entire security library into any
// Express 5 app. Import `applySecurityMiddleware` and call it once in app setup.

import type { Request, Response, NextFunction, RequestHandler } from "express";
import { verifyAccessToken, type JWTPayload } from "../auth/jwt.validator.js";
import { checkAPIRateLimit } from "../rate-limit/rate.limiter.js";
import { isIPBlocked, extractClientIP } from "../rate-limit/ip.blocker.js";
import { getSession, touchSession } from "../auth/session.guard.js";
import { logSecurityEvent } from "../audit/logger.js";
import type { UserRole } from "../auth/jwt.validator.js";
import type { Permission } from "../rbac/rbac.js";
import { hasPermission } from "../rbac/rbac.js";

// ── Express type augmentation ─────────────────────────────────────────────────

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Populated by `requireAuth` middleware after JWT verification. */
      user?: JWTPayload;
      /** Real client IP extracted from proxy headers. */
      clientIp?: string;
    }
  }
}

// ── IP extraction middleware ──────────────────────────────────────────────────

export const ipExtractor: RequestHandler = (
  req: Request,
  _res: Response,
  next: NextFunction,
): void => {
  req.clientIp = extractClientIP(
    req.socket?.remoteAddress,
    req.headers["x-forwarded-for"] as string | undefined,
  );
  next();
};

// ── IP block check middleware ─────────────────────────────────────────────────

export const ipBlockGuard: RequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const ip = req.clientIp ?? "unknown";
  const { blocked, record } = isIPBlocked(ip);
  if (blocked) {
    logSecurityEvent({
      action: "security.ip.blocked_request",
      actorId: null,
      ipAddress: ip,
      outcome: "blocked",
      metadata: { reason: record?.reason },
    });
    res.status(403).json({ error: "Access denied." });
    return;
  }
  next();
};

// ── Rate limit middleware ─────────────────────────────────────────────────────

export const apiRateLimiter: RequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const ip = req.clientIp ?? "unknown";
  const result = checkAPIRateLimit(ip);
  res.setHeader("X-RateLimit-Limit", String(result.remaining + 1));
  res.setHeader("X-RateLimit-Remaining", String(result.remaining));
  res.setHeader("X-RateLimit-Reset", result.resetAt.toISOString());

  if (!result.allowed) {
    res.setHeader(
      "Retry-After",
      Math.ceil(result.retryAfterMs / 1000).toString(),
    );
    res.status(429).json({
      error: "Too many requests. Please try again later.",
      retryAfterMs: result.retryAfterMs,
    });
    return;
  }
  next();
};

// ── Authentication middleware ─────────────────────────────────────────────────

/**
 * Require a valid JWT access token in the Authorization header.
 * Populates `req.user` on success.
 */
export const requireAuth: RequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const authHeader = req.headers["authorization"];
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Authentication required." });
    return;
  }

  const token = authHeader.slice(7);
  const result = verifyAccessToken(token);

  if (!result.valid) {
    const statusCode = result.reason === "expired" ? 401 : 403;
    res.status(statusCode).json({ error: `Token ${result.reason}.` });
    return;
  }

  // Validate active session
  const session = getSession(result.payload.sessionId);
  if (!session) {
    res.status(401).json({ error: "Session expired. Please log in again." });
    return;
  }

  touchSession(result.payload.sessionId);
  req.user = result.payload;
  next();
};

// ── RBAC middleware factory ───────────────────────────────────────────────────

/**
 * Require that the authenticated user has a specific permission.
 * MUST be used after `requireAuth`.
 */
export function requirePermission(permission: Permission): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "Authentication required." });
      return;
    }
    if (!hasPermission(req.user.role as UserRole, permission)) {
      res.status(403).json({ error: "Insufficient permissions." });
      return;
    }
    next();
  };
}

/**
 * Require that the authenticated user has one of the specified roles.
 * MUST be used after `requireAuth`.
 */
export function requireRole(...roles: UserRole[]): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "Authentication required." });
      return;
    }
    if (!roles.includes(req.user.role as UserRole)) {
      res.status(403).json({ error: "Access denied for your role." });
      return;
    }
    next();
  };
}

// ── Security headers middleware ───────────────────────────────────────────────

/** Sets conservative security HTTP headers. */
export const securityHeaders: RequestHandler = (
  _req: Request,
  res: Response,
  next: NextFunction,
): void => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=63072000; includeSubDomains; preload",
  );
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self'",
      "frame-ancestors 'none'",
    ].join("; "),
  );
  next();
};

// ── Input sanitization ────────────────────────────────────────────────────────

const SQL_INJECTION_PATTERN =
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|--|;)\b|'|\*|\/\*|\*\/)/gi;
const XSS_PATTERN = /<[^>]*>|javascript:|on\w+\s*=/gi;

function sanitizeValue(value: unknown): unknown {
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (SQL_INJECTION_PATTERN.test(trimmed)) {
      throw new Error("SQL injection pattern detected in input");
    }
    if (XSS_PATTERN.test(trimmed)) {
      throw new Error("XSS pattern detected in input");
    }
    return trimmed;
  }
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, sanitizeValue(v)]),
    );
  }
  return value;
}

/** Sanitize req.body, req.query, and req.params for SQL injection / XSS. */
export const inputSanitizer: RequestHandler = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  try {
    if (req.body) req.body = sanitizeValue(req.body);
    if (req.query) req.query = sanitizeValue(req.query) as typeof req.query;
    next();
  } catch (err) {
    const message = err instanceof Error ? err.message : "Invalid input";
    logSecurityEvent({
      action: "security.input.rejected",
      actorId: req.user?.sub ?? null,
      ipAddress: req.clientIp,
      outcome: "blocked",
      metadata: { reason: message, path: req.path },
    });
    res.status(400).json({ error: "Invalid input detected." });
  }
};

// ── CORS config helper ────────────────────────────────────────────────────────

export interface CORSOptions {
  allowedOrigins: string[];
  allowCredentials?: boolean;
}

export function buildCORSOptions(opts: CORSOptions) {
  return {
    origin: (
      origin: string | undefined,
      callback: (err: Error | null, allow?: boolean) => void,
    ): void => {
      if (!origin || opts.allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`CORS: origin "${origin}" not allowed`));
      }
    },
    credentials: opts.allowCredentials ?? true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Authorization", "Content-Type", "X-Request-ID"],
  };
}

// ── Composite setup helper ────────────────────────────────────────────────────

import type { Express } from "express";

/**
 * Apply the full security middleware stack to an Express app.
 * Call this once, before registering any routes.
 */
export function applySecurityMiddleware(
  app: Express,
  opts?: { corsOrigins?: string[] },
): void {
  app.use(ipExtractor);
  app.use(ipBlockGuard);
  app.use(securityHeaders);
  app.use(apiRateLimiter);
  app.use(inputSanitizer);

  // Disable fingerprinting
  app.disable("x-powered-by");
}

