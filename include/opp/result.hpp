#pragma once

// Planning outcome, explanation and evidence-bound result envelope.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "opp/ids.hpp"
#include "opp/plan.hpp"
#include "opp/request.hpp"
#include "opp/status.hpp"

namespace opp {

// The four-way classification the planner is required to produce, plus the two
// boundary outcomes that describe a request that was never searched.
enum class PlanOutcome : std::uint8_t {
  // At least one proven path satisfies every declared constraint.
  Feasible = 0,
  // Complete enough knowledge proves that no path can satisfy the constraints.
  Infeasible = 1,
  // Missing, stale or conflicting evidence prevents proof either way.
  Indeterminate = 2,
  // The requested semantics are outside the modelled capability surface.
  Unsupported = 3,
  // The caller cancelled the search. No candidate is published.
  Cancelled = 4,
  // The request itself was rejected before any search started.
  Refused = 5,
};

const char* PlanOutcomeName(PlanOutcome outcome) noexcept;

// Why the search could not extend a label.
enum class CutReason : std::uint8_t {
  None = 0,
  SourceAbsent,
  DestinationAbsent,
  SourceAdminDown,
  DestinationAdminDown,
  NodeExcluded,
  PortExcluded,
  SpanExcluded,
  FailureDomainExcluded,
  FailureDomainMemberLimit,
  SpanAdminDown,
  CrossConnectAdminDown,
  NoOutgoingArc,
  PortSpectrumEmpty,
  SegmentProfileAbsent,
  SegmentProfileUnknown,
  ReachDistanceExceeded,
  ReachSpanCountExceeded,
  ReachLossExceeded,
  ReachOsnrBelowMinimum,
  TotalDistanceExceeded,
  TotalSpanCountExceeded,
  TotalLossExceeded,
  RegenerationNotAllowed,
  RegenerationLimitExceeded,
  ConversionNotAllowed,
  HopLimitExceeded,
  CostLimitExceeded,
  LoopPrevented,
  Dominated,
  UnresolvedReference,
  SearchTruncated,
  UnknownQualityField,
  UnknownSpectrum,
  ConflictingEvidence,
  PartialCoverage,
  TransmitProfileUnknown,
};

const char* CutReasonName(CutReason reason) noexcept;

// Inverse of CutReasonName over the complete enumeration. Returns nullopt when
// the name is not one this runtime knows.
[[nodiscard]] std::optional<CutReason> FindCutReasonByName(std::string_view name);

// Conditions that make a conclusion unprovable or that weaken a guarantee. Bit
// flags; values are stable and never renumbered.
enum Limitation : std::uint32_t {
  kLimitationNone = 0,
  kLimitationUnknownAdjacency = 1u << 0,
  kLimitationUnknownQualityField = 1u << 1,
  kLimitationUnknownSpectrum = 1u << 2,
  kLimitationConflictingEvidence = 1u << 3,
  kLimitationStaleEvidence = 1u << 4,
  kLimitationRestoredEvidence = 1u << 5,
  kLimitationSearchTruncated = 1u << 6,
  kLimitationUnresolvedReference = 1u << 7,
  kLimitationDisjointnessGreedy = 1u << 8,
  kLimitationOptimalityNotProven = 1u << 9,
};

[[nodiscard]] std::string DescribeLimitations(std::uint32_t limitations);

// A single piece of evidence that made a conclusion unprovable.
struct Witness {
  CutReason reason = CutReason::None;
  ResourceKey resource;
  std::string detail;

  friend bool operator==(const Witness&, const Witness&) = default;
};

struct CutCount {
  CutReason reason = CutReason::None;
  std::uint64_t count = 0;

  friend bool operator==(const CutCount&, const CutCount&) = default;
};

struct PlanningStatistics {
  std::uint64_t labels_created = 0;
  std::uint64_t labels_expanded = 0;
  std::uint64_t labels_dominated = 0;
  std::uint64_t peak_frontier = 0;
  std::uint64_t arcs_examined = 0;
  std::uint64_t states_visited = 0;
  bool truncated = false;

  friend bool operator==(const PlanningStatistics&, const PlanningStatistics&) = default;
};

struct PlanningResult {
  PlanOutcome outcome = PlanOutcome::Refused;
  Status status{};
  Digest256 request_digest{};
  Digest256 snapshot_digest{};
  // Candidates in canonical order; empty unless the outcome is Feasible.
  std::vector<PlanArtifact> candidates;
  // Bounded, deduplicated and sorted list of unprovable-evidence witnesses.
  std::vector<Witness> witnesses;
  std::uint32_t limitations = kLimitationNone;
  std::vector<CutCount> cuts;
  PlanningStatistics statistics{};
  // True only when the search exhausted its space without truncation and the
  // returned best candidate is the minimum-cost feasible route under the
  // declared comparator.
  bool optimality_proven = false;
  // Stable digest over the whole result, used to prove byte-stable identity.
  Digest256 result_digest{};

  [[nodiscard]] bool HasCandidate() const noexcept { return !candidates.empty(); }
  [[nodiscard]] const PlanArtifact* Best() const noexcept {
    return candidates.empty() ? nullptr : &candidates.front();
  }

  // Canonical, human readable one-line-per-fact rendering used by the CLI.
  [[nodiscard]] std::string ExplainText() const;
  [[nodiscard]] std::string CanonicalBytes() const;
  void Seal();
};

// Produces the canonical explanation of why a request had no proven answer.
[[nodiscard]] std::string ExplainOutcome(const PlanningResult& result);

// Canonical text encoding of a result envelope, used for persistence over the
// framed transport. Round-trips exactly.
[[nodiscard]] std::string ResultToText(const PlanningResult& result);
[[nodiscard]] Expected<PlanningResult> ParseResultText(std::string_view text);

}  // namespace opp
