// ─── Booking Anomaly Detector ─────────────────────────────────────────────────
// Detects suspicious booking patterns: fake bookings, bulk cancellations,
// ghost reviews, and calendar manipulation.

// ── Types ──────────────────────────────────────────────────────────────────────

export interface BookingEvent {
  bookingId: string;
  userId: string;
  professionalId: string;
  scheduledAt: Date;
  createdAt: Date;
  ipAddress: string;
  metadata?: Record<string, unknown>;
}

export type BookingSignal =
  | "rapid_bookings"
  | "mass_cancellations"
  | "calendar_flooding"
  | "duplicate_booking"
  | "suspicious_pattern";

export interface BookingRiskAssessment {
  risky: boolean;
  signals: BookingSignal[];
  riskScore: number;
  recommendation: "allow" | "review" | "block";
}

// ── In-memory stores ──────────────────────────────────────────────────────────

const recentBookings = new Map<string, BookingEvent[]>();
const recentCancellations = new Map<string, number>();
const professionalCalendarHits = new Map<string, BookingEvent[]>();

const BOOKING_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const MAX_BOOKINGS_PER_HOUR = 5;
const MAX_CANCELLATIONS_PER_DAY = 8;
const MAX_CALENDAR_HITS_PER_HOUR = 15;

function pruneOldBookings(userId: string): void {
  const cutoff = Date.now() - BOOKING_WINDOW_MS;
  const history = recentBookings.get(userId) ?? [];
  recentBookings.set(
    userId,
    history.filter((e) => e.createdAt.getTime() > cutoff),
  );
}

function pruneCalendarHits(professionalId: string): void {
  const cutoff = Date.now() - BOOKING_WINDOW_MS;
  const hits = professionalCalendarHits.get(professionalId) ?? [];
  professionalCalendarHits.set(
    professionalId,
    hits.filter((e) => e.createdAt.getTime() > cutoff),
  );
}

/**
 * Assess a new booking event for suspicious patterns.
 */
export function assessBookingRisk(event: BookingEvent): BookingRiskAssessment {
  const signals: BookingSignal[] = [];
  let riskScore = 0;

  // 1. Rapid bookings from same user
  pruneOldBookings(event.userId);
  const userHistory = recentBookings.get(event.userId) ?? [];
  if (userHistory.length >= MAX_BOOKINGS_PER_HOUR) {
    signals.push("rapid_bookings");
    riskScore += 40;
  }

  // 2. Duplicate booking (same user + professional + slot)
  const duplicate = userHistory.some(
    (e) =>
      e.professionalId === event.professionalId &&
      Math.abs(e.scheduledAt.getTime() - event.scheduledAt.getTime()) <
        60 * 1000,
  );
  if (duplicate) {
    signals.push("duplicate_booking");
    riskScore += 60;
  }

  // 3. Calendar flooding (too many bookings targeting same professional)
  pruneCalendarHits(event.professionalId);
  const calHits = professionalCalendarHits.get(event.professionalId) ?? [];
  if (calHits.length >= MAX_CALENDAR_HITS_PER_HOUR) {
    signals.push("calendar_flooding");
    riskScore += 35;
  }

  // Record the event
  userHistory.push(event);
  recentBookings.set(event.userId, userHistory);

  calHits.push(event);
  professionalCalendarHits.set(event.professionalId, calHits);

  riskScore = Math.min(100, riskScore);

  let recommendation: BookingRiskAssessment["recommendation"];
  if (riskScore >= 70) {
    recommendation = "block";
  } else if (riskScore >= 35) {
    recommendation = "review";
  } else {
    recommendation = "allow";
  }

  return {
    risky: recommendation === "block",
    signals: [...new Set(signals)],
    riskScore,
    recommendation,
  };
}

/**
 * Record a booking cancellation for mass-cancel detection.
 */
export function recordCancellation(userId: string): { blocked: boolean } {
  const count = (recentCancellations.get(userId) ?? 0) + 1;
  recentCancellations.set(userId, count);
  return { blocked: count >= MAX_CANCELLATIONS_PER_DAY };
}

/** Reset cancellation counter (e.g. after manual review). */
export function clearCancellations(userId: string): void {
  recentCancellations.delete(userId);
}
