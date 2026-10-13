// ─── Role-Based Access Control (RBAC) ────────────────────────────────────────
// Defines roles, permissions, and enforcement helpers used across all services.

import type { UserRole } from "../auth/jwt.validator.js";

// ── Permission registry ───────────────────────────────────────────────────────

export type Permission =
  // Booking permissions
  | "booking:create"
  | "booking:read:own"
  | "booking:read:all"
  | "booking:cancel:own"
  | "booking:cancel:any"
  // Payment permissions
  | "payment:initiate"
  | "payment:read:own"
  | "payment:read:all"
  | "payment:refund"
  // User management
  | "user:read:own"
  | "user:read:all"
  | "user:update:own"
  | "user:update:any"
  | "user:delete:any"
  // Professional/service management
  | "professional:update:own"
  | "professional:manage:all"
  | "service:create"
  | "service:update:own"
  | "service:delete:own"
  | "service:delete:any"
  // Admin operations
  | "admin:dashboard:read"
  | "admin:audit:read"
  | "admin:ip:block"
  | "admin:user:lock"
  | "admin:fraud:review"
  | "admin:config:write"
  // Content
  | "review:create"
  | "review:delete:own"
  | "review:delete:any";

// ── Role → permissions map ────────────────────────────────────────────────────

const rolePermissions: Record<UserRole, Set<Permission>> = {
  customer: new Set<Permission>([
    "booking:create",
    "booking:read:own",
    "booking:cancel:own",
    "payment:initiate",
    "payment:read:own",
    "user:read:own",
    "user:update:own",
    "review:create",
    "review:delete:own",
  ]),

  professional: new Set<Permission>([
    "booking:read:own",
    "booking:cancel:own",
    "payment:read:own",
    "user:read:own",
    "user:update:own",
    "professional:update:own",
    "service:create",
    "service:update:own",
    "service:delete:own",
    "review:create",
    "review:delete:own",
  ]),

  "admin-web": new Set<Permission>([
    // Admins have all permissions
    "booking:create",
    "booking:read:own",
    "booking:read:all",
    "booking:cancel:own",
    "booking:cancel:any",
    "payment:initiate",
    "payment:read:own",
    "payment:read:all",
    "payment:refund",
    "user:read:own",
    "user:read:all",
    "user:update:own",
    "user:update:any",
    "user:delete:any",
    "professional:update:own",
    "professional:manage:all",
    "service:create",
    "service:update:own",
    "service:delete:own",
    "service:delete:any",
    "admin:dashboard:read",
    "admin:audit:read",
    "admin:ip:block",
    "admin:user:lock",
    "admin:fraud:review",
    "admin:config:write",
    "review:create",
    "review:delete:own",
    "review:delete:any",
  ]),
};

// ── RBAC enforcement helpers ──────────────────────────────────────────────────

/**
 * Check whether a role has a specific permission.
 */
export function hasPermission(role: UserRole, permission: Permission): boolean {
  return rolePermissions[role]?.has(permission) ?? false;
}

/**
 * Assert that a role has a permission — throws if not.
 * Use in route handlers to gate access.
 */
export function assertPermission(role: UserRole, permission: Permission): void {
  if (!hasPermission(role, permission)) {
    throw new RBACError(role, permission);
  }
}

/**
 * Return all permissions granted to a role.
 */
export function getPermissions(role: UserRole): Permission[] {
  return Array.from(rolePermissions[role] ?? []);
}

/**
 * Check whether a user can access a resource they own vs. any resource.
 * Resolves ":own" vs ":all" automatically based on ownership.
 */
export function canAccessResource(
  role: UserRole,
  action: string,
  isOwner: boolean,
): boolean {
  if (isOwner) {
    return (
      hasPermission(role, `${action}:own` as Permission) ||
      hasPermission(role, `${action}:all` as Permission)
    );
  }
  return hasPermission(role, `${action}:all` as Permission);
}

// ── RBAC error ────────────────────────────────────────────────────────────────

export class RBACError extends Error {
  readonly role: UserRole;
  readonly permission: Permission;

  constructor(role: UserRole, permission: Permission) {
    super(`Role "${role}" does not have permission "${permission}"`);
    this.name = "RBACError";
    this.role = role;
    this.permission = permission;
  }
}
