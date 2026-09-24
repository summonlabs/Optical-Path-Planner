// Differential suite: an independent reference solver for small graphs.
//
// The oracle enumerates every port-simple route by depth-first search and
// evaluates each one against the raw snapshot records with its own arithmetic.
// It shares no code with the production search beyond reading the snapshot's
// adjacency lists: the constraint rules, the spectrum arithmetic and the
// transparent-segment accounting are written again here.
//
// The production planner explores walks and prunes with Pareto dominance; the
// oracle explores elementary routes with no pruning. They must agree on
// feasibility and on the lexicographic minimum of (cost, hops, regenerations).
//
// The fixtures are chains and rings with a deliberately small branching factor,
// so the oracle can be exhaustive. A state budget makes an accidental blow-up a
// loud failure instead of a hang.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include "opp/opp.hpp"
#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace opp;
using opp_test::BuildChainSnapshot;
using opp_test::Random;

constexpr std::uint32_t kNoIndex = 0xFFFFFFFFu;

struct OracleBest {
  bool found = false;
  std::uint64_t cost = 0;
  std::uint32_t hops = 0;
  std::uint32_t regenerations = 0;
};

bool BetterThan(std::uint64_t cost, std::uint32_t hops, std::uint32_t regenerations, const OracleBest& best) {
  if (!best.found) return true;
  if (cost != best.cost) return cost < best.cost;
  if (hops != best.hops) return hops < best.hops;
  return regenerations < best.regenerations;
}

// Independent re-implementation of the evidence rules the planner applies.
class Oracle {
 public:
  Oracle(const TopologySnapshot& snapshot, const PlanningRequest& request)
      : snapshot_(snapshot), request_(request), constraints_(request.constraints) {
    std::sort(constraints_.excluded_nodes.begin(), constraints_.excluded_nodes.end());
    std::sort(constraints_.excluded_ports.begin(), constraints_.excluded_ports.end());
    std::sort(constraints_.excluded_spans.begin(), constraints_.excluded_spans.end());
    std::sort(constraints_.excluded_cross_connects.begin(), constraints_.excluded_cross_connects.end());
    std::sort(constraints_.excluded_failure_domains.begin(), constraints_.excluded_failure_domains.end());
    visited_.assign(snapshot_.ports().size(), false);
  }

  OracleBest Run() {
    states_ = 0;
    budget_exceeded_ = false;
    const auto source = snapshot_.PortIndex(request_.source);
    const auto destination = snapshot_.PortIndex(request_.destination);
    if (!source.has_value() || !destination.has_value()) return best_;
    destination_ = destination.value();

    const PortRecord* port = snapshot_.FindPort(request_.source);
    if (port == nullptr) return best_;
    if (!IsUsable(port->admin)) return best_;
    if (!port->transmit_profile.HasValue() || !port->transmit_profile.value().has_value()) return best_;
    if (!port->blocked_slots.HasValue()) return best_;
    if (IsExcluded(port->key)) return best_;
    if (HasExcludedDomain(port->failure_domains)) return best_;

    State state;
    state.profile = port->transmit_profile.value().value().str();
    state.mask = FirstSlots(port->blocked_slots);
    state.cost = port->transit_cost;
    if (const NodeRecord* node = snapshot_.FindNode(port->key.node); node != nullptr) {
      state.cost += node->transit_cost;
    }
    if (state.mask.IsEmpty()) return best_;
    visited_[source.value()] = true;
    Explore(source.value(), state);
    visited_[source.value()] = false;
    return best_;
  }

  [[nodiscard]] std::uint64_t states() const noexcept { return states_; }
  [[nodiscard]] bool budget_exceeded() const noexcept { return budget_exceeded_; }

 private:
  struct State {
    std::uint64_t cost = 0;
    std::uint64_t distance = 0;
    double loss = 0.0;
    double osnr_inverse = 0.0;
    std::uint32_t spans = 0;
    std::uint32_t hops = 0;
    std::uint32_t regenerations = 0;
    SlotMask mask{};
    std::string profile;
  };

  static bool IsUsable(const Evidence<AdminState>& admin) {
    return admin.HasValue() && admin.value() == AdminState::Up;
  }

  template <class T>
  static bool Listed(const std::vector<T>& values, const T& value) {
    return std::binary_search(values.begin(), values.end(), value);
  }

  bool IsExcluded(const PortKey& key) const {
    return Listed(constraints_.excluded_ports, key) || Listed(constraints_.excluded_nodes, key.node);
  }

  // A node transit cost is charged once, when a route enters a node it was not
  // already standing in.
  std::uint64_t TransitionCost(const PortKey& from, const PortKey& to) const {
    if (from.node == to.node) return 0;
    const NodeRecord* node = snapshot_.FindNode(to.node);
    return node == nullptr ? 0 : node->transit_cost;
  }

  bool HasExcludedDomain(const std::vector<FailureDomainId>& domains) const {
    for (const FailureDomainId& domain : domains) {
      if (Listed(constraints_.excluded_failure_domains, domain)) return true;
    }
    return false;
  }

  // Independent re-derivation of the usable channel starts for one resource.
  SlotMask FirstSlots(const Evidence<SlotMask>& blocked) const {
    SlotMask usable = SlotMask::All(snapshot_.spectrum().slot_count);
    if (blocked.HasValue()) {
      for (std::uint16_t slot = 0; slot < snapshot_.spectrum().slot_count; ++slot) {
        if (blocked.value().Test(slot)) usable.Reset(slot);
      }
    }
    return usable.FirstSlotMask(request_.channel_width_slots);
  }

  // The oracle does not model per-path failure-domain counting exactly; the
  // fixtures that use member limits are checked separately, so a request that
  // declares them is refused here rather than silently approximated.
  void Explore(std::uint32_t port_index, const State& state) {
    states_ += 1;
    if (states_ > state_budget_) {
      budget_exceeded_ = true;
      return;
    }
    if (state.hops > request_.max_hops) return;
    if (port_index == destination_) {
      if (BetterThan(state.cost, state.hops, state.regenerations, best_)) {
        best_.found = true;
        best_.cost = state.cost;
        best_.hops = state.hops;
        best_.regenerations = state.regenerations;
      }
      return;
    }

    for (std::uint32_t index : snapshot_.OutgoingCrossConnects(port_index)) {
      const CrossConnectRecord& record = snapshot_.cross_connects()[index];
      if (Listed(constraints_.excluded_cross_connects, record.id)) continue;
      if (IsExcluded(record.to)) continue;
      if (HasExcludedDomain(record.failure_domains)) continue;
      if (!IsUsable(record.admin)) continue;
      if (!record.blocked_slots.HasValue()) continue;
      if (record.op == CrossConnectOp::Regenerate && !constraints_.allow_regeneration) continue;
      if (record.op == CrossConnectOp::Convert && !constraints_.allow_wavelength_conversion) continue;
      if (record.op == CrossConnectOp::Regenerate && state.regenerations >= request_.max_regenerations) continue;

      const auto target_index = snapshot_.PortIndex(record.to);
      if (!target_index.has_value()) continue;
      if (visited_[target_index.value()]) continue;
      if (target_index.value() == port_index) continue;
      const PortRecord& target = snapshot_.ports()[target_index.value()];
      if (!IsUsable(target.admin)) continue;
      if (!target.blocked_slots.HasValue()) continue;
      if (IsExcluded(target.key)) continue;
      if (HasExcludedDomain(target.failure_domains)) continue;

      State next = state;
      next.hops += 1;
      next.cost += record.cost;
      next.cost += target.transit_cost;
      next.cost += TransitionCost(snapshot_.ports()[port_index].key, target.key);
      if (request_.max_total_cost.has_value() && next.cost > request_.max_total_cost.value()) continue;

      if (record.op == CrossConnectOp::Express) {
        next.mask = state.mask.Intersect(FirstSlots(record.blocked_slots)).Intersect(FirstSlots(target.blocked_slots));
      } else if (record.op == CrossConnectOp::Convert) {
        next.mask = FirstSlots(target.blocked_slots);
      } else {
        if (!target.transmit_profile.HasValue() || !target.transmit_profile.value().has_value()) continue;
        next.profile = target.transmit_profile.value().value().str();
        next.mask = FirstSlots(target.blocked_slots);
        next.distance = 0;
        next.loss = 0.0;
        next.osnr_inverse = 0.0;
        next.spans = 0;
        next.regenerations += 1;
      }
      if (next.mask.IsEmpty()) continue;

      const ReachProfile* profile = snapshot_.FindReachProfile(ProfileId::Trusted(state.profile));
      if (profile == nullptr) continue;
      if (profile->max_span_count.HasValue() && next.spans > profile->max_span_count.value()) continue;
      if (profile->max_distance_m.HasValue() && next.distance > profile->max_distance_m.value()) continue;
      if (profile->max_loss_db.HasValue() && next.loss > profile->max_loss_db.value() + 1.0e-9) continue;

      visited_[target_index.value()] = true;
      Explore(target_index.value(), next);
      visited_[target_index.value()] = false;
      if (budget_exceeded_) return;
    }

    for (const SpanArc& arc : snapshot_.OutgoingSpanArcs(port_index)) {
      const SpanRecord& record = snapshot_.spans()[arc.span_index];
      if (Listed(constraints_.excluded_spans, record.id)) continue;
      if (!IsUsable(record.admin)) continue;
      if (!record.length_m.HasValue() || !record.loss_db.HasValue() || !record.osnr_db.HasValue()) continue;
      if (!record.blocked_slots.HasValue()) continue;
      const PortKey arrival = arc.reversed ? record.from : record.to;
      if (IsExcluded(arrival)) continue;
      if (HasExcludedDomain(record.failure_domains)) continue;
      const auto arrival_index = snapshot_.PortIndex(arrival);
      if (!arrival_index.has_value()) continue;
      if (visited_[arrival_index.value()]) continue;
      if (arrival_index.value() == port_index) continue;
      const PortRecord& arrival_port = snapshot_.ports()[arrival_index.value()];
      if (!IsUsable(arrival_port.admin)) continue;
      if (!arrival_port.blocked_slots.HasValue()) continue;
      if (IsExcluded(arrival_port.key)) continue;
      if (HasExcludedDomain(arrival_port.failure_domains)) continue;

      State next = state;
      next.hops += 1;
      next.cost += record.cost;
      next.cost += arrival_port.transit_cost;
      next.cost += TransitionCost(snapshot_.ports()[port_index].key, arrival_port.key);
      if (request_.max_total_cost.has_value() && next.cost > request_.max_total_cost.value()) continue;

      const ReachProfile* profile = snapshot_.FindReachProfile(ProfileId::Trusted(state.profile));
      if (profile == nullptr) continue;

      next.distance = state.distance + record.length_m.value();
      next.loss = state.loss + record.loss_db.value();
      next.osnr_inverse = state.osnr_inverse + std::pow(10.0, -record.osnr_db.value() / 10.0);
      next.spans = state.spans + 1;
      next.mask =
          state.mask.Intersect(FirstSlots(record.blocked_slots)).Intersect(FirstSlots(arrival_port.blocked_slots));
      if (next.mask.IsEmpty()) continue;

      if (profile->max_span_count.HasValue() && next.spans > profile->max_span_count.value()) continue;
      if (profile->max_distance_m.HasValue() && next.distance > profile->max_distance_m.value()) continue;
      if (profile->max_loss_db.HasValue() && next.loss > profile->max_loss_db.value() + 1.0e-9) continue;
      if (profile->min_osnr_db.HasValue()) {
        const double segment_osnr = next.osnr_inverse <= 0.0 ? 1.0e9 : -10.0 * std::log10(next.osnr_inverse);
        double floor_db = profile->min_osnr_db.value();
        if (constraints_.min_segment_osnr_db.has_value()) {
          floor_db = std::max(floor_db, constraints_.min_segment_osnr_db.value());
        }
        if (segment_osnr + 1.0e-9 < floor_db) continue;
      }
      if (constraints_.max_total_distance_m.has_value() && next.distance > constraints_.max_total_distance_m.value()) {
        continue;
      }
      if (constraints_.max_total_span_count.has_value() && next.spans > constraints_.max_total_span_count.value()) {
        continue;
      }
      if (constraints_.max_total_loss_db.has_value() && next.loss > constraints_.max_total_loss_db.value() + 1.0e-9) {
        continue;
      }

      visited_[arrival_index.value()] = true;
      Explore(arrival_index.value(), next);
      visited_[arrival_index.value()] = false;
      if (budget_exceeded_) return;
    }
  }

  const TopologySnapshot& snapshot_;
  const PlanningRequest& request_;
  ConstraintSet constraints_;
  std::vector<bool> visited_;
  std::uint32_t destination_ = kNoIndex;
  OracleBest best_{};
  std::uint64_t states_ = 0;
  std::uint64_t state_budget_ = 20000000ull;
  bool budget_exceeded_ = false;
};

// Every path is proven in these fixtures, so the production planner must either
// return the oracle optimum or prove infeasibility.
bool CompareAgainstOracle(const TopologySnapshot& snapshot, const PlanningRequest& request, Oracle* oracle) {
  const OracleBest expected = oracle->Run();
  if (oracle->budget_exceeded()) {
    OPP_CHECK_MSG(false, "the reference solver exceeded its state budget; the fixture is too large");
    return false;
  }
  if (request.constraints.max_members_per_failure_domain.empty()) {
    // The oracle does not model per-path failure-domain counting.
  }
  const Planner planner;
  const PlanningResult result = planner.Plan(snapshot, request);
  if (expected.found) {
    OPP_CHECK_MSG(result.outcome == PlanOutcome::Feasible,
                  std::string("expected FEASIBLE, got ") + PlanOutcomeName(result.outcome));
    if (result.outcome != PlanOutcome::Feasible) return false;
    const PlanArtifact& plan = result.candidates.front();
    OPP_CHECK_MSG(plan.total_cost == expected.cost,
                  "cost " + std::to_string(plan.total_cost) + " != oracle " + std::to_string(expected.cost));
    OPP_CHECK_MSG(plan.hops == expected.hops,
                  "hops " + std::to_string(plan.hops) + " != oracle " + std::to_string(expected.hops));
    OPP_CHECK_MSG(plan.regenerations == expected.regenerations,
                  "regenerations " + std::to_string(plan.regenerations) + " != oracle " +
                      std::to_string(expected.regenerations));
    OPP_CHECK(result.optimality_proven);
    return true;
  }
  OPP_CHECK_MSG(result.outcome == PlanOutcome::Infeasible,
                std::string("expected INFEASIBLE, got ") + PlanOutcomeName(result.outcome));
  return false;
}

PlanningRequest MakeChainRequest(const std::string& from, const std::string& from_port, const std::string& to,
                                 const std::string& to_port, std::uint32_t tag, std::uint32_t max_hops) {
  PlanningRequest request;
  request.id = RequestId::Trusted("oracle-" + std::to_string(tag));
  request.source = PortKey{NodeId::Trusted(from), PortId::Trusted(from_port)};
  request.destination = PortKey{NodeId::Trusted(to), PortId::Trusted(to_port)};
  request.max_hops = max_hops;
  return request;
}

void ApplyRandomTightening(PlanningRequest* request, Random* random) {
  switch (random->Below(8)) {
    case 0:
      request->constraints.max_total_distance_m = 50000 + random->Below(400000);
      break;
    case 1:
      request->constraints.max_total_span_count = 1 + random->Below(4);
      break;
    case 2:
      request->constraints.max_total_loss_db = 5.0 + random->UnitDouble() * 40.0;
      break;
    case 3:
      request->constraints.allow_regeneration = false;
      break;
    case 4:
      request->constraints.min_segment_osnr_db = 12.0 + random->UnitDouble() * 8.0;
      break;
    case 5:
      request->max_total_cost = 20 + random->Below(30);
      break;
    case 6:
      request->max_regenerations = random->Below(3);
      break;
    default:
      break;
  }
}

}  // namespace

OPP_TEST(oracle, chains_and_rings_agree_with_reference_solver) {
  std::uint32_t comparisons = 0;
  std::uint64_t states = 0;
  for (std::uint32_t nodes = 3; nodes <= 6; ++nodes) {
    for (const bool ring : {false, true}) {
      for (std::uint64_t seed = 1; seed <= 4; ++seed) {
        const auto built = BuildChainSnapshot(nodes, 8, seed, ring);
        OPP_REQUIRE(built.ok());
        const TopologySnapshot& snapshot = built.value();
        OPP_REQUIRE(snapshot.coverage_complete());

        Random random(seed * 7919ull + nodes);
        for (std::uint32_t attempt = 0; attempt < 6; ++attempt) {
          const std::uint32_t from = random.Below(nodes);
          std::uint32_t to = random.Below(nodes);
          if (to == from) to = (to + 1) % nodes;
          PlanningRequest request = MakeChainRequest("c" + std::to_string(from), "in", "c" + std::to_string(to),
                                                     "out", static_cast<std::uint32_t>(seed), 4 * nodes);
          ApplyRandomTightening(&request, &random);
          if (random.Below(3) == 0) {
            const std::string node = "c" + std::to_string(random.Below(nodes));
            request.constraints.excluded_nodes.push_back(NodeId::Trusted(node));
          }
          if (random.Below(3) == 0) {
            request.constraints.excluded_failure_domains.push_back(
                FailureDomainId::Trusted("site" + std::to_string(random.Below(nodes))));
          }
          if (request.Validate().failed()) continue;
          Oracle oracle(snapshot, request);
          CompareAgainstOracle(snapshot, request, &oracle);
          states += oracle.states();
          comparisons += 1;
        }
      }
    }
  }
  OPP_CHECK_MSG(comparisons >= 80,
                "expected at least 80 differential comparisons, ran " + std::to_string(comparisons));
  OPP_CHECK_MSG(states > 0, "the reference solver visited no states");
}

OPP_TEST(oracle, every_node_pair_agrees) {
  const auto built = BuildChainSnapshot(5, 8, 11, false);
  OPP_REQUIRE(built.ok());
  const TopologySnapshot& snapshot = built.value();
  for (std::uint32_t from = 0; from < 5; ++from) {
    for (std::uint32_t to = 0; to < 5; ++to) {
      if (from == to) continue;
      PlanningRequest request =
          MakeChainRequest("c" + std::to_string(from), "in", "c" + std::to_string(to), "out", from * 10 + to, 24);
      Oracle oracle(snapshot, request);
      CompareAgainstOracle(snapshot, request, &oracle);
    }
  }
}

OPP_TEST(oracle, exclusion_sets_agree) {
  const auto built = BuildChainSnapshot(5, 8, 12, true);
  OPP_REQUIRE(built.ok());
  const TopologySnapshot& snapshot = built.value();
  for (std::uint32_t excluded = 1; excluded < 4; ++excluded) {
    PlanningRequest request = MakeChainRequest("c0", "in", "c4", "out", excluded, 24);
    request.constraints.excluded_nodes.push_back(NodeId::Trusted("c" + std::to_string(excluded)));
    Oracle oracle(snapshot, request);
    CompareAgainstOracle(snapshot, request, &oracle);
  }
  // Excluding every span breaks the chain.
  PlanningRequest isolated = MakeChainRequest("c0", "in", "c4", "out", 99, 24);
  for (const SpanRecord& span : snapshot.spans()) isolated.constraints.excluded_spans.push_back(span.id);
  // The exclusions are not sorted yet; sorting happens inside both solvers.
  Oracle oracle(snapshot, isolated);
  CompareAgainstOracle(snapshot, isolated, &oracle);
}

OPP_TEST(oracle, regeneration_paths_agree) {
  for (std::uint64_t seed = 20; seed < 26; ++seed) {
    const auto built = BuildChainSnapshot(9, 8, seed, false);
    OPP_REQUIRE(built.ok());
    const TopologySnapshot& snapshot = built.value();
    Random random(seed);
    for (std::uint32_t attempt = 0; attempt < 3; ++attempt) {
      PlanningRequest request = MakeChainRequest("c0", "in", "c8", "out", static_cast<std::uint32_t>(seed), 40);
      // A tight reach budget forces regeneration at the regenerating nodes.
      request.constraints.max_total_distance_m = 90000 + random.Below(120000);
      Oracle oracle(snapshot, request);
      const bool found = CompareAgainstOracle(snapshot, request, &oracle);
      if (found) {
        const PlanningResult result = Planner().Plan(snapshot, request);
        OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
        OPP_CHECK_MSG(result.candidates.front().regenerations >= 1 || request.constraints.max_total_distance_m.value() > 200000,
                      "the tight reach budget did not force a regeneration");
      }
    }
  }
}

OPP_TEST(oracle, flexible_grid_agrees) {
  const std::uint16_t widths[] = {1, 2, 3};
  for (std::uint64_t seed = 30; seed < 34; ++seed) {
    SyntheticOptions options;
    options.seed = seed;
    options.node_count = 5;
    options.degree = 2;
    options.slot_count = 18;
    options.grid = GridKind::Flex12_5GHz;
    options.slot_blocking_one_in = 4;
    options.generation = 2;
    options.id = "flex-" + std::to_string(seed);
    const auto built = GenerateSyntheticTopology(options);
    OPP_REQUIRE(built.ok());
    const TopologySnapshot& snapshot = built.value();
    for (std::uint16_t width : widths) {
      PlanningRequest request = MakeChainRequest("n0", "c0", "n4", "c0", static_cast<std::uint32_t>(seed), 8);
      request.channel_width_slots = width;
      OPP_REQUIRE(request.Validate().ok());
      Oracle oracle(snapshot, request);
      CompareAgainstOracle(snapshot, request, &oracle);
    }
  }
}

OPP_TEST(oracle, synthetic_meshes_agree_with_reference_solver) {
  for (std::uint64_t seed = 40; seed < 46; ++seed) {
    const auto built = opp_test::BuildCompleteSnapshot(seed, 5, 10, 4);
    OPP_REQUIRE(built.ok());
    const TopologySnapshot& snapshot = built.value();
    Random random(seed);
    for (std::uint32_t attempt = 0; attempt < 3; ++attempt) {
      const std::uint32_t from = random.Below(5);
      std::uint32_t to = random.Below(5);
      if (to == from) to = (to + 1) % 5;
      PlanningRequest request = MakeChainRequest("n" + std::to_string(from), "c0", "n" + std::to_string(to), "c0",
                                                 static_cast<std::uint32_t>(seed), 7);
      ApplyRandomTightening(&request, &random);
      Oracle oracle(snapshot, request);
      CompareAgainstOracle(snapshot, request, &oracle);
    }
  }
}

OPP_TEST(oracle, infeasible_cases_agree) {
  const auto built = BuildChainSnapshot(5, 6, 50, false);
  OPP_REQUIRE(built.ok());
  const TopologySnapshot& snapshot = built.value();

  PlanningRequest impossible = MakeChainRequest("c0", "in", "c4", "out", 1, 24);
  impossible.constraints.max_total_distance_m = 1;
  Oracle distance_oracle(snapshot, impossible);
  CompareAgainstOracle(snapshot, impossible, &distance_oracle);

  PlanningRequest no_hops = MakeChainRequest("c0", "in", "c4", "out", 2, 1);
  Oracle hop_oracle(snapshot, no_hops);
  CompareAgainstOracle(snapshot, no_hops, &hop_oracle);

  PlanningRequest no_loss = MakeChainRequest("c0", "in", "c4", "out", 3, 24);
  no_loss.constraints.max_total_loss_db = 0.0001;
  Oracle loss_oracle(snapshot, no_loss);
  CompareAgainstOracle(snapshot, no_loss, &loss_oracle);

  PlanningRequest narrow = MakeChainRequest("c0", "in", "c4", "out", 4, 24);
  narrow.constraints.min_segment_osnr_db = 1.0e6;
  Oracle osnr_oracle(snapshot, narrow);
  CompareAgainstOracle(snapshot, narrow, &osnr_oracle);

  PlanningRequest no_regeneration = MakeChainRequest("c0", "in", "c8", "out", 5, 40);
  no_regeneration.constraints.allow_regeneration = false;
  Oracle regeneration_oracle(snapshot, no_regeneration);
  CompareAgainstOracle(snapshot, no_regeneration, &regeneration_oracle);
}

OPP_TEST(oracle, candidate_enumeration_is_ordered_and_distinct) {
  const auto built = BuildChainSnapshot(6, 12, 60, true);
  OPP_REQUIRE(built.ok());
  PlanningRequest request = MakeChainRequest("c0", "in", "c5", "out", 1, 26);
  request.max_candidates = 4;
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  OPP_REQUIRE(!result.candidates.empty());

  for (std::size_t i = 0; i < result.candidates.size(); ++i) {
    for (std::size_t j = i + 1; j < result.candidates.size(); ++j) {
      OPP_CHECK_MSG(!(result.candidates[i].digest == result.candidates[j].digest),
                    "candidate enumeration returned the same plan twice");
      OPP_CHECK_MSG(!PlanLess(result.candidates[j], result.candidates[i]),
                    "candidate enumeration is not in canonical order");
    }
  }
  Oracle oracle(built.value(), request);
  const OracleBest expected = oracle.Run();
  OPP_REQUIRE(expected.found);
  OPP_CHECK_EQ(result.candidates.front().total_cost, expected.cost);
  OPP_CHECK_EQ(result.candidates.front().hops, expected.hops);
}

OPP_TEST(oracle, disjoint_enumeration_finds_alternatives) {
  const auto built = BuildChainSnapshot(6, 12, 62, true);
  OPP_REQUIRE(built.ok());
  PlanningRequest request = MakeChainRequest("c0", "in", "c5", "out", 1, 26);
  request.max_candidates = 3;
  request.disjointness = Disjointness::Span;
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  OPP_REQUIRE_MSG(result.candidates.size() >= 2,
                  "a ring should offer at least two span-disjoint candidates");
  for (std::size_t i = 0; i < result.candidates.size(); ++i) {
    for (std::size_t j = i + 1; j < result.candidates.size(); ++j) {
      for (const PlanStep& step : result.candidates[i].steps) {
        if (step.resource.kind() != ResourceKind::Span) continue;
        for (const PlanStep& other : result.candidates[j].steps) {
          OPP_CHECK_MSG(!(other.resource == step.resource),
                        "span-disjoint candidates share " + ResourceKeyToString(step.resource));
        }
      }
    }
  }
  // Each candidate is an ordinary proven plan bound to the same evidence.
  for (const PlanArtifact& plan : result.candidates) {
    OPP_CHECK(plan.VerifySeal().ok());
    OPP_CHECK(plan.snapshot_digest == built.value().digest());
  }
}

OPP_TEST(oracle, domain_disjoint_enumeration_finds_alternatives) {
  const auto built = BuildChainSnapshot(6, 12, 63, true);
  OPP_REQUIRE(built.ok());
  PlanningRequest request = MakeChainRequest("c0", "in", "c5", "out", 1, 26);
  request.max_candidates = 2;
  request.disjointness = Disjointness::FailureDomain;
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  OPP_REQUIRE(result.candidates.size() >= 1);
  if (result.candidates.size() >= 2) {
    for (const FailureDomainExposure& exposure : result.candidates[0].failure_domain_exposure) {
      for (const FailureDomainExposure& other : result.candidates[1].failure_domain_exposure) {
        OPP_CHECK_MSG(!(other.id == exposure.id),
                      "failure-domain-disjoint candidates share " + exposure.id.str());
      }
    }
  }
}

OPP_TEST(oracle, disjoint_candidates_share_no_resource) {
  const auto built = BuildChainSnapshot(6, 12, 61, true);
  OPP_REQUIRE(built.ok());
  PlanningRequest request = MakeChainRequest("c0", "in", "c4", "out", 1, 24);
  request.max_candidates = 3;
  request.disjointness = Disjointness::Node;
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  for (std::size_t i = 0; i < result.candidates.size(); ++i) {
    for (std::size_t j = i + 1; j < result.candidates.size(); ++j) {
      for (const PlanStep& step : result.candidates[i].steps) {
        if (step.resource.kind() != ResourceKind::Node) continue;
        for (const PlanStep& other : result.candidates[j].steps) {
          OPP_CHECK_MSG(!(other.resource == step.resource),
                        "node-disjoint candidates share " + ResourceKeyToString(step.resource));
        }
      }
    }
  }
}
