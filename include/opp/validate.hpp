#pragma once

// Plan validation against current evidence.
//
// Two independent checks are available:
//   * ValidatePlanBindings compares the generations and digests a plan is bound
//     to against the evidence a consumer currently holds. It answers "may I still
//     act on this plan?" and never re-runs the search.
//   * RevalidatePlan re-derives every eligibility decision of the plan against
//     the current snapshot. It is the stronger check and is what a consumer
//     should run when the bound generation is unchanged but the snapshot digest
//     is not.
//
// Neither check grants authority. A valid plan is still only a recommendation.

#include <cstdint>
#include <string>
#include <vector>

#include "opp/plan.hpp"
#include "opp/result.hpp"
#include "opp/status.hpp"
#include "opp/topology.hpp"

namespace opp {

enum class PlanValidity : std::uint8_t {
  Valid = 0,
  // At least one bound generation no longer matches the current evidence.
  Stale = 1,
  // The snapshot digest or id changed even though generations match.
  ContentMismatch = 2,
  // Evidence required by the plan is absent from the snapshot.
  MissingEvidence = 3,
  // The stored artifact failed its own seal or could not be parsed.
  IntegrityFailure = 4,
  // The artifact was produced by an unsupported rule or format revision.
  Unsupported = 5,
  // The artifact or the snapshot was structurally rejected.
  Refused = 6,
  // The current snapshot is restored evidence and the caller did not accept it.
  NotFresh = 7,
};

const char* PlanValidityName(PlanValidity validity) noexcept;

struct SourceMismatch {
  SourceId source;
  Generation bound = 0;
  Generation current = 0;
  bool present = false;

  friend bool operator==(const SourceMismatch&, const SourceMismatch&) = default;
};

struct RevalidationFailure {
  std::uint32_t step_index = 0;
  ResourceKey resource;
  CutReason reason = CutReason::None;
  std::string detail;

  friend bool operator==(const RevalidationFailure&, const RevalidationFailure&) = default;
};

struct ValidationPolicy {
  // When false, a snapshot that a service restored from persistence is treated
  // as not fresh and validation fails with NotFresh.
  bool accept_restored_evidence = false;
  // When true, generation mismatches are reported but the plan is revalidated
  // anyway to describe what changed.
  bool revalidate_on_mismatch = false;
};

struct ValidationReport {
  PlanValidity validity = PlanValidity::Refused;
  Status status{};
  std::vector<SourceMismatch> source_mismatches;
  Digest256 bound_snapshot_digest{};
  Digest256 current_snapshot_digest{};
  // True when RevalidatePlan actually re-derived the plan's eligibility.
  bool revalidated = false;
  std::vector<RevalidationFailure> failures;

  [[nodiscard]] bool ok() const noexcept { return validity == PlanValidity::Valid; }
  [[nodiscard]] std::string ExplainText() const;
};

[[nodiscard]] ValidationReport ValidatePlanBindings(const PlanArtifact& plan,
                                                    const TopologySnapshot& snapshot,
                                                    const ValidationPolicy& policy = ValidationPolicy());

[[nodiscard]] ValidationReport RevalidatePlan(const PlanArtifact& plan,
                                              const TopologySnapshot& snapshot,
                                              const ValidationPolicy& policy = ValidationPolicy());

}  // namespace opp
