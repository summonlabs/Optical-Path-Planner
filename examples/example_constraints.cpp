// Constraint handling: exclusions, failure-domain member limits, quality
// ceilings, disjoint candidate selection and the four-way outcome.

#include <iostream>
#include <string>

#include "opp/opp.hpp"

namespace {

void Show(const char* label, const opp::PlanningResult& result) {
  std::cout << label << ": " << opp::PlanOutcomeName(result.outcome);
  if (result.status.failed()) std::cout << " (" << opp::StatusCodeName(result.status.code) << ")";
  std::cout << " candidates=" << result.candidates.size() << " optimality_proven="
            << (result.optimality_proven ? "true" : "false") << "\n";
  for (const opp::CutCount& cut : result.cuts) {
    std::cout << "    cut " << opp::CutReasonName(cut.reason) << " x" << cut.count << "\n";
  }
}

}  // namespace

int main() {
  using namespace opp;

  SyntheticOptions options;
  options.seed = 11;
  options.node_count = 12;
  options.degree = 3;
  options.slot_count = 16;
  options.generation = 3;
  const auto generated = GenerateSyntheticTopology(options);
  if (!generated.ok()) {
    std::cerr << generated.status().detail << "\n";
    return 1;
  }
  const TopologySnapshot& snapshot = generated.value();

  PlanningRequest base;
  base.id = RequestId::Trusted("constraints");
  base.source = PortKey{NodeId::Trusted("n0"), PortId::Trusted("c0")};
  base.destination = PortKey{NodeId::Trusted("n6"), PortId::Trusted("c0")};
  base.max_candidates = 1;

  const Planner planner;

  Show("plain", planner.Plan(snapshot, base));

  PlanningRequest limited = base;
  limited.constraints.max_total_distance_m = 40000;
  Show("total distance ceiling", planner.Plan(snapshot, limited));

  PlanningRequest hop_limited = base;
  hop_limited.max_hops = 3;
  Show("hop ceiling", planner.Plan(snapshot, hop_limited));

  PlanningRequest domain_excluded = base;
  domain_excluded.constraints.excluded_failure_domains.push_back(FailureDomainId::Trusted("site0"));
  domain_excluded.constraints.excluded_failure_domains.push_back(FailureDomainId::Trusted("site1"));
  Show("two sites excluded", planner.Plan(snapshot, domain_excluded));

  PlanningRequest source_excluded = base;
  source_excluded.constraints.excluded_nodes.push_back(NodeId::Trusted("n0"));
  Show("source node excluded", planner.Plan(snapshot, source_excluded));

  PlanningRequest diversity = base;
  diversity.max_candidates = 3;
  diversity.disjointness = Disjointness::Node;
  const PlanningResult diverse = planner.Plan(snapshot, diversity);
  Show("node-disjoint candidates", diverse);
  for (const PlanArtifact& plan : diverse.candidates) {
    std::cout << "    candidate " << plan.DigestHex().substr(0, 16) << " cost=" << plan.total_cost
              << " hops=" << plan.hops << " regenerations=" << plan.regenerations << "\n";
  }

  PlanningRequest unsupported = base;
  unsupported.constraints.allow_repeated_resources = true;
  Show("unsupported semantics", planner.Plan(snapshot, unsupported));

  PlanningRequest stale = base;
  stale.required_source_generations[SourceId::Trusted("synthetic-generator")] = 99;
  Show("stale evidence requirement", planner.Plan(snapshot, stale));

  return 0;
}
