#pragma once

// Planning request.

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "opp/constraints.hpp"
#include "opp/ids.hpp"
#include "opp/limits.hpp"
#include "opp/status.hpp"

namespace opp {

inline constexpr std::uint32_t kRequestFormatVersion = 1;

struct PlanningRequest {
  std::uint32_t format_version = kRequestFormatVersion;
  RequestId id;
  PortKey source;
  PortKey destination;

  // Channel width in spectrum slots. Must be 1 for a fixed 50 GHz grid.
  std::uint16_t channel_width_slots = 1;

  // Number of candidates to return, 1..kMaxCandidates. Candidates are ordered
  // by the canonical candidate comparator.
  std::uint32_t max_candidates = 1;
  std::uint32_t max_regenerations = kDefaultMaxRegenerations;
  std::uint32_t max_hops = kDefaultMaxHops;
  std::optional<std::uint64_t> max_total_cost;

  Disjointness disjointness = Disjointness::None;
  ConstraintSet constraints;

  // Minimum generation the caller requires from each named source. A snapshot
  // that cannot meet a requirement yields INDETERMINATE with a STALE reason;
  // it never yields FEASIBLE.
  std::map<SourceId, Generation> required_source_generations;
  std::optional<Generation> required_snapshot_generation;
  // When set, the snapshot digest must match exactly, otherwise the request is
  // INDETERMINATE with a STALE reason.
  std::optional<Digest256> expected_snapshot_digest;

  // Evidence that a service restored from persistence is not fresh. Accepting
  // it is an explicit caller decision, never a runtime default.
  bool accept_restored_evidence = false;

  // Search bounds. Ceilings, not timeouts.
  std::uint64_t max_search_expansions = kDefaultSearchExpansions;
  std::uint64_t max_search_labels = kDefaultSearchLabels;

  // Structural validation. Returns REFUSED-worthy detail on failure.
  [[nodiscard]] Status Validate() const;

  [[nodiscard]] std::string DigestText() const;
};

// Canonical byte encoding of a request, used for the request digest.
[[nodiscard]] std::string RequestCanonicalBytes(const PlanningRequest& request);
[[nodiscard]] Digest256 ComputeRequestDigest(const PlanningRequest& request);

}  // namespace opp
