#pragma once

// Internal deterministic label search.
//
// The search is a Pareto label-correcting best-first search over port states.
// Labels carry the resource vector (cost, distance, loss, inverse OSNR, span
// count, hops, regenerations) and the running set of still-usable channel start
// slots. A label is pruned only when another retained label at the same
// (port, reach profile) is at least as good in every dimension and is at least
// as provable; that relation is extension monotone, so pruning never removes an
// optimum.
//
// The search explores walks rather than elementary routes. That is deliberate:
// removing a cycle from a walk can only lower cost and the resource vector and
// can only widen the usable channel set, so the optimum over walks equals the
// optimum over elementary routes. The caller strips cycles when it materialises
// a plan, which is also where the resource accounting is recomputed from
// scratch.

#include <cstdint>
#include <vector>

#include "opp/planner.hpp"
#include "opp/request.hpp"
#include "opp/result.hpp"
#include "opp/topology.hpp"

namespace opp {
namespace detail {

enum class ArcKind : std::uint8_t {
  Span = 0,
  CrossConnect = 1,
};

struct ArcRef {
  ArcKind kind = ArcKind::Span;
  std::uint32_t index = 0;
  bool reversed = false;

  friend bool operator==(const ArcRef&, const ArcRef&) = default;
};

struct RawPath {
  std::vector<ArcRef> arcs;
  std::uint64_t cost = 0;
  std::uint32_t hops = 0;
  std::uint32_t regenerations = 0;
  bool proven = false;
};

struct SearchOutcome {
  Status status{};
  // True when the search stopped early on a proof rather than on a bound.
  bool exhausted = false;
  bool proved_optimum = false;
  std::vector<RawPath> paths;
  std::uint32_t limitations = kLimitationNone;
  std::vector<Witness> witnesses;
  std::vector<CutCount> cuts;
  PlanningStatistics statistics{};
};

[[nodiscard]] SearchOutcome RunSearch(const TopologySnapshot& snapshot, const PlanningRequest& request,
                                      const PlannerOptions& options, const CancelToken& cancel,
                                      const SearchObserver& observer);

// Rebuilds a plan from an arc sequence by re-evaluating every decision against
// the snapshot. Returns a failure when the sequence is not realisable, which can
// only happen if the caller hands over a sequence the search did not produce.
[[nodiscard]] Expected<PlanArtifact> BuildPlan(const TopologySnapshot& snapshot, const PlanningRequest& request,
                                               const Digest256& request_digest, const std::vector<ArcRef>& arcs,
                                               Digest256* out_digest);

// Removes repeated ports from an arc sequence. The result is port-simple and
// therefore resource-simple; it is never worse than the input in cost, resource
// usage or usable channel set.
[[nodiscard]] std::vector<ArcRef> StripCycles(const TopologySnapshot& snapshot, const PortKey& source,
                                              const std::vector<ArcRef>& arcs);

// Port an arc arrives at.
[[nodiscard]] Expected<PortKey> ArrivalPort(const TopologySnapshot& snapshot, const ArcRef& arc);

// Port an arc departs from.
[[nodiscard]] Expected<PortKey> DeparturePort(const TopologySnapshot& snapshot, const ArcRef& arc);

}  // namespace detail
}  // namespace opp
