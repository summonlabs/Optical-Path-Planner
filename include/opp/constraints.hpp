#pragma once

// The declared constraint set. Every entry is explicit evidence supplied by the
// caller; the planner never invents a default that would make a constraint
// silently disappear.

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include "opp/ids.hpp"
#include "opp/status.hpp"

namespace opp {

// Pairwise relationship required between returned candidates.
enum class Disjointness : std::uint8_t {
  None = 0,
  // No node may be shared by two candidates.
  Node = 1,
  // No span may be shared by two candidates.
  Span = 2,
  // No failure domain may be shared by two candidates.
  FailureDomain = 3,
};

const char* DisjointnessName(Disjointness value) noexcept;
[[nodiscard]] bool ParseDisjointness(std::string_view text, Disjointness* out) noexcept;

struct ConstraintSet {
  // Hard exclusions.
  std::vector<NodeId> excluded_nodes;
  std::vector<PortKey> excluded_ports;
  std::vector<SpanId> excluded_spans;
  std::vector<CrossConnectId> excluded_cross_connects;
  std::vector<FailureDomainId> excluded_failure_domains;

  // Upper bound on the number of path members (nodes plus spans) that may
  // belong to a failure domain. A domain without an entry is unbounded.
  std::map<FailureDomainId, std::uint32_t> max_members_per_failure_domain;

  // End-to-end quality ceilings applied on top of the per-segment reach budget.
  std::optional<std::uint64_t> max_total_distance_m;
  std::optional<std::uint32_t> max_total_span_count;
  std::optional<double> max_total_loss_db;
  // Additional floor on every transparent segment minimum OSNR. The reach
  // profile floor always applies as well; this can only tighten it.
  std::optional<double> min_segment_osnr_db;

  // Regeneration and conversion policy.
  bool allow_regeneration = true;
  bool allow_wavelength_conversion = true;

  // Semantics that this model does not implement. They are declared explicitly
  // so that a caller asking for them receives UNSUPPORTED instead of a plan
  // computed under different semantics than the caller assumed.
  bool require_spectrum_continuity_across_regeneration = false;
  bool allow_repeated_resources = false;

  // Structural validation: bounds, duplicates and value domains. Does not
  // consult any topology.
  [[nodiscard]] Status Validate() const;
};

}  // namespace opp
