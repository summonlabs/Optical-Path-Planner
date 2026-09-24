// Quickstart: build a snapshot, plan a route, read the sealed artifact.
//
// Every value in this example is hand written so the expected answer can be
// checked by reading it: a:in -> a:east -> s-ab -> b:west -> b:east -> s-bc ->
// c:west -> c:out.

#include <iostream>
#include <string>

#include "opp/opp.hpp"

int main() {
  using namespace opp;

  const auto built = BuildExampleTopology();
  if (!built.ok()) {
    std::cerr << "snapshot: " << built.status().detail << "\n";
    return 1;
  }
  const TopologySnapshot& snapshot = built.value();

  std::cout << "snapshot " << snapshot.id().str() << " digest " << snapshot.digest().ToHex() << "\n";
  std::cout << "  nodes " << snapshot.nodes().size() << " ports " << snapshot.ports().size() << " spans "
            << snapshot.spans().size() << " cross-connects " << snapshot.cross_connects().size() << "\n";

  PlanningRequest request;
  request.id = RequestId::Trusted("quickstart");
  request.source = PortKey{NodeId::Trusted("a"), PortId::Trusted("in")};
  request.destination = PortKey{NodeId::Trusted("c"), PortId::Trusted("out")};
  request.max_candidates = 2;

  const Planner planner;
  const PlanningResult result = planner.Plan(snapshot, request);
  std::cout << result.ExplainText();

  if (result.outcome != PlanOutcome::Feasible) {
    std::cerr << "expected a feasible route\n";
    return 1;
  }

  const PlanArtifact& plan = result.candidates.front();
  std::cout << "best plan digest " << plan.DigestHex() << "\n";
  std::cout << "bound sources:\n";
  for (const SourceBinding& binding : plan.bound_sources) {
    std::cout << "  " << binding.source.str() << " generation " << binding.generation << " contribution "
              << binding.snapshot_contribution.ToHex().substr(0, 16) << "...\n";
  }
  std::cout << "required spectrum:\n";
  for (const PlanReservation& reservation : plan.reservations) {
    std::cout << "  " << ResourceKeyToString(reservation.resource) << " slot " << reservation.channel.first_slot
              << " width " << reservation.channel.width_slots << "\n";
  }

  // A plan is only meaningful while the evidence it is bound to is current.
  const ValidationReport validation = ValidatePlanBindings(plan, snapshot);
  std::cout << "validation: " << PlanValidityName(validation.validity) << "\n";

  const auto reparsed = ParsePlanArtifact(plan.CanonicalBytes());
  if (!reparsed.ok() || !(reparsed.value().digest == plan.digest)) {
    std::cerr << "plan artifact did not round trip\n";
    return 1;
  }
  std::cout << "plan artifact round trip ok\n";
  return 0;
}
