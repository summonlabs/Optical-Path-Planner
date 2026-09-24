#pragma once

// Candidate plan artifact.
//
// A plan is a recommendation, never an execution authority. It records the
// ordered resources of a route, the spectrum it would occupy, the capability and
// quality evidence it relies on, its failure-domain exposure and the exact
// evidence generations it was computed from. The artifact is immutable once
// sealed and its digest is byte-stable for identical inputs.

#include <cstdint>
#include <string>
#include <vector>

#include "opp/ids.hpp"
#include "opp/spectrum.hpp"
#include "opp/status.hpp"
#include "opp/topology.hpp"

namespace opp {

enum class StepKind : std::uint8_t {
  Node = 0,
  Port = 1,
  Span = 2,
  CrossConnect = 3,
};

const char* StepKindName(StepKind kind) noexcept;

// Bit flags recording why a step was eligible. The mask is part of the plan
// digest, so its values are stable and never renumbered.
enum EligibilityReason : std::uint32_t {
  kReasonNone = 0,
  kReasonAdminUp = 1u << 0,
  kReasonNotExcluded = 1u << 1,
  kReasonPortAdmitted = 1u << 2,
  kReasonSpectrumAvailable = 1u << 3,
  kReasonWithinReachDistance = 1u << 4,
  kReasonWithinReachSpans = 1u << 5,
  kReasonWithinReachLoss = 1u << 6,
  kReasonWithinReachOsnr = 1u << 7,
  kReasonRegenerationBoundary = 1u << 8,
  kReasonWavelengthConversion = 1u << 9,
  kReasonFailureDomainWithinLimit = 1u << 10,
  kReasonSourceEvidencePresent = 1u << 11,
  kReasonSegmentStart = 1u << 12,
  kReasonTransmitProfileKnown = 1u << 13,
};

[[nodiscard]] std::string DescribeEligibility(std::uint32_t reason_bits);

struct PlanStep {
  std::uint32_t index = 0;
  StepKind kind = StepKind::Node;
  ResourceKey resource;
  std::uint32_t segment_index = 0;
  std::uint32_t reason_bits = 0;
  std::uint64_t cost = 0;

  friend bool operator==(const PlanStep&, const PlanStep&) = default;
};

struct PlanSpanUse {
  SpanId id;
  PortKey from;
  PortKey to;
  bool reversed = false;
  std::uint64_t length_m = 0;
  double loss_db = 0.0;
  double osnr_db = 0.0;
  std::uint64_t cost = 0;
  // Slot the span would occupy. The channel is constant between two wavelength
  // changing operations, so a transparent section can carry several values.
  std::uint16_t first_slot = 0;
  std::vector<FailureDomainId> failure_domains;

  friend bool operator==(const PlanSpanUse&, const PlanSpanUse&) = default;
};

// One transparent segment: a maximal run of resources over which a single
// channel is preserved and impairment accumulates.
struct PlanSegment {
  std::uint32_t index = 0;
  ProfileId profile;
  std::vector<PlanSpanUse> spans;
  std::uint64_t distance_m = 0;
  double loss_db = 0.0;
  double osnr_db = 0.0;
  std::uint32_t span_count = 0;
  // Number of distinct wavelength runs inside this transparent section.
  std::uint32_t channel_runs = 0;
  bool ended_by_regeneration = false;
  ResourceKey regeneration_resource;

  friend bool operator==(const PlanSegment&, const PlanSegment&) = default;
};

// Spectrum the route would require. The planner has no reservation authority;
// these entries state what a downstream reservation owner would have to grant.
struct PlanReservation {
  ResourceKey resource;
  Channel channel;
  std::uint32_t segment_index = 0;

  friend bool operator==(const PlanReservation&, const PlanReservation&) = default;
};

// Evidence the plan relies on, recorded so that a consumer can see exactly which
// published facts made the route eligible.
struct PlanAssumption {
  ResourceKey resource;
  std::string field;
  std::string value;

  friend bool operator==(const PlanAssumption&, const PlanAssumption&) = default;
};

struct FailureDomainExposure {
  FailureDomainId id;
  std::uint32_t member_count = 0;
  // 0 means no declared limit applied to this domain.
  std::uint32_t limit = 0;

  friend bool operator==(const FailureDomainExposure&, const FailureDomainExposure&) = default;
};

// A source generation the plan is bound to. A consumer must reject the plan once
// any of these no longer matches the current evidence.
struct SourceBinding {
  SourceId source;
  Generation generation = 0;
  Digest256 snapshot_contribution{};

  friend bool operator==(const SourceBinding&, const SourceBinding&) = default;
  friend auto operator<=>(const SourceBinding&, const SourceBinding&) = default;
};

struct PlanArtifact {
  std::uint32_t format_version = 1;
  std::uint32_t rule_version = 1;
  RequestId request_id;
  Digest256 request_digest{};
  SnapshotId snapshot_id;
  Generation snapshot_generation = 0;
  Digest256 snapshot_digest{};
  std::vector<SourceBinding> bound_sources;

  PortKey source;
  PortKey destination;
  std::vector<PlanStep> steps;
  std::vector<PlanSegment> segments;
  std::vector<PlanReservation> reservations;
  std::vector<PlanAssumption> capability_assumptions;
  std::vector<PlanAssumption> quality_assumptions;
  std::vector<FailureDomainExposure> failure_domain_exposure;

  std::uint16_t channel_width_slots = 1;
  std::uint64_t total_cost = 0;
  std::uint64_t total_distance_m = 0;
  double total_loss_db = 0.0;
  std::uint32_t hops = 0;
  std::uint32_t regenerations = 0;
  Digest256 digest{};

  // Canonical bytes of the sealed artifact, including the digest trailer.
  [[nodiscard]] std::string CanonicalBytes() const;
  // Bytes over which the digest is computed: everything except the digest field.
  [[nodiscard]] std::string DigestPayload() const;

  // Recomputes and stores the sealed digest. Called by the planner before the
  // artifact is exposed; calling it twice on unchanged content is idempotent.
  void Seal();

  // Verifies that the stored digest matches the content.
  [[nodiscard]] Status VerifySeal() const;

  [[nodiscard]] std::string DigestHex() const;

  // Resource sequence, used by the canonical candidate comparator.
  [[nodiscard]] std::string ResourceSequenceKey() const;
};

// Domain-separated digest of the artifact payload.
[[nodiscard]] Digest256 ComputePlanDigest(const PlanArtifact& plan);

// Parses the canonical artifact byte encoding (as produced by CanonicalBytes).
[[nodiscard]] Expected<PlanArtifact> ParsePlanArtifact(std::string_view bytes);

// Canonical candidate ordering: total cost, then hops, then regenerations, then
// the lexicographic resource sequence. Returns true when lhs sorts before rhs.
[[nodiscard]] bool PlanLess(const PlanArtifact& lhs, const PlanArtifact& rhs);

}  // namespace opp
