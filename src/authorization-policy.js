export const BOOKING_POLICY_ID = "summit-stone-booking-demo-v1";

const ALLOWED_ROLES = new Set(["booking_agent", "operations_lead"]);
const READ_ONLY_ACTIONS = new Set(["lookup_availability", "quote_itinerary"]);
const REVIEW_ACTIONS = new Set(["create_temporary_hold"]);
const DENIED_ACTIONS = new Set([
  "confirm_booking",
  "change_traveler_identity",
  "cancel_booking",
  "issue_refund",
  "apply_discount"
]);

const result = (decision, reason) => ({
  decision,
  policyId: BOOKING_POLICY_ID,
  reason
});

export function authorizeBookingAction({
  actorRole,
  proposedAction,
  resourceScope,
  classification
}) {
  if (!ALLOWED_ROLES.has(actorRole)) return result("deny", "actor_role_not_allowed");
  if (resourceScope !== "synthetic_booking") {
    return result("deny", "resource_scope_not_allowed");
  }
  if (DENIED_ACTIONS.has(proposedAction)) {
    return result("deny", "action_not_enabled");
  }
  if (REVIEW_ACTIONS.has(proposedAction)) {
    return result("review", "explicit_human_confirmation_required");
  }
  if (!READ_ONLY_ACTIONS.has(proposedAction)) {
    return result("deny", "unknown_action");
  }
  if (!classification || classification.confidence < 0.75) {
    return result("review", "classification_confidence_too_low");
  }
  if (
    classification.actionClass !== "read_only" ||
    classification.stateChanging ||
    classification.humanReview ||
    classification.risk !== "low"
  ) {
    return result("review", "model_classification_requires_review");
  }
  return result("allow", "read_only_action_allowed");
}
