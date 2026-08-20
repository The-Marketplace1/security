// ─── Payment Anomaly Detector ─────────────────────────────────────────────────
// Detects suspicious payment patterns: duplicate charges, velocity spikes,
// unusual amounts, and idempotency enforcement.

// ── Types ──────────────────────────────────────────────────────────────────────

export interface PaymentEvent {
  paymentId: string;
  userId: string;
  amountCents: number;
  currency: string;
  method: string;
  ipAddress: string;
  timestamp: Date;
  metadata?: Record<string, unknown>;
}

export type FraudSignal =
  | "duplicate_payment"
  | "velocity_exceeded"
  | "amount_anomaly"
  | "multiple_card_attempts"
  | "suspicious_ip_pattern";

export interface FraudAssessment {
  fraudulent: boolean;
  signals: FraudSignal[];
  riskScore: number; // 0–100
  recommendation: "allow" | "review" | "block";
}

// ── In-memory stores ──────────────────────────────────────────────────────────

// Idempotency key store: paymentId → first seen timestamp
const processedPayments = new Map<string, Date>();

// Per-user recent payment window (last 1 hour)
const userPaymentHistory = new Map<string, PaymentEvent[]>();

// Per-user card attempt tracking
const failedCardAttempts = new Map<string, number>();

// ── Idempotency ───────────────────────────────────────────────────────────────

/**
 * Returns true if this paymentId has already been processed.
 * MUST be called before executing any charge.
 */
export function isDuplicatePayment(paymentId: string): boolean {
  return processedPayments.has(paymentId);
}

/** Mark a paymentId as processed. Call after successful charge. */
export function markPaymentProcessed(paymentId: string): void {
  processedPayments.set(paymentId, new Date());
}

// ── Fraud assessment ──────────────────────────────────────────────────────────

const VELOCITY_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const VELOCITY_MAX_COUNT = 10;
const VELOCITY_MAX_TOTAL_CENTS = 500_000; // $5,000
const UNUSUAL_AMOUNT_CENTS = 100_000; // $1,000 single transaction

function pruneOldEvents(userId: string): void {
  const cutoff = Date.now() - VELOCITY_WINDOW_MS;
  const history = userPaymentHistory.get(userId) ?? [];
  userPaymentHistory.set(
    userId,
    history.filter((e) => e.timestamp.getTime() > cutoff),
  );
}

/**
 * Assess a payment event for fraud signals.
 * Returns a risk assessment — call BEFORE processing the payment.
 */
export function assessPaymentFraud(event: PaymentEvent): FraudAssessment {
  const signals: FraudSignal[] = [];
  let riskScore = 0;

  // 1. Duplicate payment check
  if (isDuplicatePayment(event.paymentId)) {
    signals.push("duplicate_payment");
    riskScore += 80;
  }

  // 2. Velocity checks
  pruneOldEvents(event.userId);
  const history = userPaymentHistory.get(event.userId) ?? [];

  if (history.length >= VELOCITY_MAX_COUNT) {
    signals.push("velocity_exceeded");
    riskScore += 40;
  }

  const totalInWindow = history.reduce((sum, e) => sum + e.amountCents, 0);
  if (totalInWindow + event.amountCents > VELOCITY_MAX_TOTAL_CENTS) {
    signals.push("velocity_exceeded");
    riskScore = Math.min(100, riskScore + 35);
  }

  // 3. Unusual amount
  if (event.amountCents > UNUSUAL_AMOUNT_CENTS) {
    signals.push("amount_anomaly");
    riskScore += 20;
  }

  // 4. Multiple failed card attempts
  const failCount = failedCardAttempts.get(event.userId) ?? 0;
  if (failCount >= 3) {
    signals.push("multiple_card_attempts");
    riskScore += 30;
  }

  riskScore = Math.min(100, riskScore);

  let recommendation: FraudAssessment["recommendation"];
  if (riskScore >= 75) {
    recommendation = "block";
  } else if (riskScore >= 40) {
    recommendation = "review";
  } else {
    recommendation = "allow";
  }

  // Record the event in history (regardless of assessment — used for velocity)
  history.push(event);
  userPaymentHistory.set(event.userId, history);

  return {
    fraudulent: recommendation === "block",
    signals: [...new Set(signals)],
    riskScore,
    recommendation,
  };
}

/** Record a failed payment card attempt for a user. */
export function recordFailedCardAttempt(userId: string): void {
  failedCardAttempts.set(userId, (failedCardAttempts.get(userId) ?? 0) + 1);
}

/** Clear failed card attempts after successful payment. */
export function clearFailedCardAttempts(userId: string): void {
  failedCardAttempts.delete(userId);
}

