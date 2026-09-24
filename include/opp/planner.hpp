#pragma once

// The planner: deterministic multi-criteria label search over the sealed
// snapshot, with an explicit four-way outcome.
//
// Outcome precedence, applied in this order:
//   1. REFUSED        the request failed structural validation
//   2. UNSUPPORTED    the request asks for semantics outside the modelled surface
//   3. INDETERMINATE  bound evidence is stale, missing or conflicting
//   4. FEASIBLE       at least one proven candidate satisfies every constraint
//   5. INFEASIBLE     the search exhausted its space and every reachable label was
//                     cut for a proven reason
//   6. INDETERMINATE  the search reached a knowledge frontier or its bounds
//   7. CANCELLED      the caller cancelled; no candidate is published
//
// Cancellation is checked at every label expansion. A cancelled search produces
// no candidate and never seals a plan.

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "opp/request.hpp"
#include "opp/result.hpp"
#include "opp/status.hpp"
#include "opp/topology.hpp"

namespace opp {

// Cooperative cancellation handle. Copies share one flag. A default constructed
// token is a live, never-cancelled token, so callers that do not care about
// cancellation can pass nothing at all.
class CancelToken {
 public:
  CancelToken() : flag_(std::make_shared<std::atomic<bool>>(false)) {}

  void Request() const noexcept { flag_->store(true, std::memory_order_release); }
  [[nodiscard]] bool IsRequested() const noexcept { return flag_->load(std::memory_order_acquire); }

 private:
  std::shared_ptr<std::atomic<bool>> flag_;
};

// Observation hook. Invoked after each label expansion, and only from the thread
// running the search. It must be cheap and must not re-enter the planner. It
// exists so that callers and tests can cancel deterministically at a known
// expansion boundary instead of relying on wall-clock timing.
using SearchObserver = std::function<void(const PlanningStatistics&)>;

struct PlannerOptions {
  // Absolute ceilings, applied even when a request asks for more.
  std::uint64_t expansion_ceiling = kMaxSearchExpansionsCeiling;
  std::uint64_t label_ceiling = kMaxSearchLabelsCeiling;
  // When false, witness collection is skipped (faster, less explanatory).
  bool collect_witnesses = true;
};

class Planner {
 public:
  Planner() = default;
  explicit Planner(PlannerOptions options) : options_(options) {}

  [[nodiscard]] const PlannerOptions& options() const noexcept { return options_; }

  // Computes up to request.max_candidates candidates. The returned result is
  // sealed and byte-stable for identical snapshot, request and options.
  [[nodiscard]] PlanningResult Plan(const TopologySnapshot& snapshot,
                                    const PlanningRequest& request,
                                    const CancelToken& cancel = CancelToken(),
                                    const SearchObserver& observer = SearchObserver()) const;

 private:
  PlannerOptions options_{};
};

// The admissible-op policy derived from a constraint set. Exposed for inspection
// and for tests that need to reason about the same rule table as the planner.
[[nodiscard]] bool IsOpAllowed(const ConstraintSet& constraints, CrossConnectOp op) noexcept;

}  // namespace opp
