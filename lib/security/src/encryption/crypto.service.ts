// ─── Crypto Service ───────────────────────────────────────────────────────────
// AES-256-GCM authenticated encryption for sensitive fields (PII, OTP secrets,
// payment metadata). Uses Node.js built-in `crypto` — no native dependencies.

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  timingSafeEqual,
  createHash,
} from "node:crypto";
import { securityConfig } from "../config/security.config.js";

// ── Constants ─────────────────────────────────────────────────────────────────

const ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12; // 96-bit IV recommended for GCM
const TAG_BYTES = 16; // 128-bit auth tag
const KEY_BYTES = 32; // 256-bit key

// ── Key derivation ────────────────────────────────────────────────────────────

function deriveKey(): Buffer {
  const rawKey = securityConfig.encryptionKey;
  if (rawKey.length === 64) {
    // Assume hex-encoded 32-byte key
    return Buffer.from(rawKey, "hex");
  }
  // Derive via scrypt if the key isn't already 32 bytes hex
  return scryptSync(rawKey, "marketplace-security-salt", KEY_BYTES);
}

// ── Encryption ────────────────────────────────────────────────────────────────

export interface EncryptedPayload {
  /** Base64-encoded: iv (12 bytes) + ciphertext + auth tag (16 bytes) */
  ciphertext: string;
  /** Algorithm identifier for future rotation */
  alg: "aes-256-gcm";
}

/**
 * Encrypt arbitrary plaintext.
 * The returned object is safe to store in a database column.
 */
export function encryptSensitiveData(plaintext: string): EncryptedPayload {
  const key = deriveKey();
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  // Pack: iv | ciphertext | tag → base64
  const packed = Buffer.concat([iv, encrypted, tag]);
  return { ciphertext: packed.toString("base64"), alg: "aes-256-gcm" };
}

/**
 * Decrypt a payload produced by `encryptSensitiveData`.
 * Throws on authentication failure — never silently returns garbage.
 */
export function decryptData(payload: EncryptedPayload): string {
  const key = deriveKey();
  const packed = Buffer.from(payload.ciphertext, "base64");

  const iv = packed.subarray(0, IV_BYTES);
  const tag = packed.subarray(packed.length - TAG_BYTES);
  const ciphertext = packed.subarray(IV_BYTES, packed.length - TAG_BYTES);

  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  return decipher.update(ciphertext) + decipher.final("utf8");
}

// ── Password hashing (scrypt) ─────────────────────────────────────────────────
// scrypt is used here because it's built into Node.js.
// bcrypt/argon2 can be swapped in if your environment supports native modules.

const SCRYPT_KEYLEN = 64;
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

export function hashPassword(password: string): string {
  const salt = randomBytes(32).toString("hex");
  const derived = scryptSync(password, salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
  return `${salt}:${derived.toString("hex")}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const [salt, hashHex] = storedHash.split(":");
  if (!salt || !hashHex) return false;
  const derived = scryptSync(password, salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
  const storedBuf = Buffer.from(hashHex, "hex");
  // Constant-time comparison to prevent timing attacks
  return timingSafeEqual(derived, storedBuf);
}

// ── Secure token generation ───────────────────────────────────────────────────

/** Generate a cryptographically secure random token (URL-safe base64). */
export function generateSecureToken(byteLength = 32): string {
  return randomBytes(byteLength).toString("base64url");
}

/** Generate a numeric OTP of the specified digit length. */
export function generateOTP(digits = 6): string {
  const max = Math.pow(10, digits);
  const bytes = randomBytes(4);
  const num = bytes.readUInt32BE(0) % max;
  return num.toString().padStart(digits, "0");
}

/** Hash a value with SHA-256 for non-reversible fingerprinting (e.g. device ID). */
export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

// ── Secure key management placeholder ────────────────────────────────────────

/**
 * In production, replace this with a call to your KMS (AWS KMS, GCP KMS,
 * HashiCorp Vault, etc.). This placeholder returns the configured key.
 */
export function secureKeyManagement(): { keyId: string; createdAt: Date } {
  return {
    keyId: sha256(securityConfig.encryptionKey).slice(0, 16),
    createdAt: new Date(),
  };
}
