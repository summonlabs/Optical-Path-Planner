// A downstream consumer of the installed OpticalPathPlanner package.
//
// It builds a small evidence set, asks the planner for a candidate, validates the sealed artifact
// against the evidence it is bound to, and proves that a replayed plan is rejected once the evidence
// generation moves. Nothing here reaches into the Optical Path Planner source tree.

#include <iostream>
#include <optional>
#include <string>
#include <utility>

#include "opp/opp.hpp"

namespace {

using namespace opp;

PortKey Key(const char* node, const char* port) {
  return PortKey{NodeId::Trusted(node), PortId::Trusted(port)};
}

// Builds a two node fabric with one span between them and a published reach profile.
Expected<TopologySnapshot> BuildFabric(Generation generation) {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("consumer-fabric"));
  builder.SetGeneration(generation);
  SpectrumModel spectrum;
  spectrum.grid = GridKind::Fixed50GHz;
  spectrum.slot_count = 8;
  builder.SetSpectrum(spectrum);

  const SourceId source = SourceId::Trusted("consumer-evidence");
  SourceRecord source_record;
  source_record.id = source;
  source_record.generation = generation;
  Status status = builder.AddSource(source_record);
  if (status.failed()) return status;

  ReachProfile profile;
  profile.id = ProfileId::Trusted("reach-200km");
  profile.max_distance_m = Evidence<std::uint64_t>::Known(200000);
  profile.max_span_count = Evidence<std::uint32_t>::Known(4);
  profile.max_loss_db = Evidence<double>::Known(20.0);
  profile.min_osnr_db = Evidence<double>::Known(14.0);
  profile.source = source;
  profile.generation = generation;
  status = builder.AddReachProfile(profile);
  if (status.failed()) return status;

  for (const char* name : {"a", "b"}) {
    NodeRecord node;
    node.id = NodeId::Trusted(name);
    node.kind = NodeKind::ReconfigurableOadm;
    node.failure_domains.push_back(FailureDomainId::Trusted(std::string("site-") + name));
    node.admin = Evidence<AdminState>::Known(AdminState::Up);
    node.source = source;
    node.generation = generation;
    status = builder.AddNode(std::move(node));
    if (status.failed()) return status;
    for (const char* port_name : {"in", "out", "line"}) {
      PortRecord port;
      port.key = Key(name, port_name);
      port.role = std::string(port_name) == "line" ? PortRole::Line : PortRole::Client;
      port.admin = Evidence<AdminState>::Known(AdminState::Up);
      port.transmit_profile =
          Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(profile.id));
      port.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
      port.source = source;
      port.generation = generation;
      status = builder.AddPort(std::move(port));
      if (status.failed()) return status;
    }
    CrossConnectRecord cross_connect;
    cross_connect.id = CrossConnectId::Trusted(std::string("xc-") + name);
    cross_connect.from = Key(name, "in");
    cross_connect.to = Key(name, "line");
    cross_connect.op = CrossConnectOp::Express;
    cross_connect.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
    cross_connect.admin = Evidence<AdminState>::Known(AdminState::Up);
    cross_connect.source = source;
    cross_connect.generation = generation;
    status = builder.AddCrossConnect(std::move(cross_connect));
    if (status.failed()) return status;
  }

  SpanRecord span;
  span.id = SpanId::Trusted("fiber-a-b");
  span.from = Key("a", "line");
  span.to = Key("b", "line");
  span.length_m = Evidence<std::uint64_t>::Known(90000);
  span.loss_db = Evidence<double>::Known(12.0);
  span.osnr_db = Evidence<double>::Known(30.0);
  span.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  span.failure_domains.push_back(FailureDomainId::Trusted("fiber-a-b"));
  span.admin = Evidence<AdminState>::Known(AdminState::Up);
  span.cost = 3;
  span.source = source;
  span.generation = generation;
  status = builder.AddSpan(std::move(span));
  if (status.failed()) return status;

  return builder.Build();
}

}  // namespace

int main() {
  const auto fabric = BuildFabric(7);
  if (!fabric.ok()) {
    std::cerr << "fabric: " << fabric.status().detail << "\n";
    return 1;
  }
  std::cout << "installed package version " << VersionString() << "\n";
  std::cout << "fabric " << fabric.value().id().str() << " digest " << fabric.value().digest().ToHex()
            << "\n";

  PlanningRequest request;
  request.id = RequestId::Trusted("consumer");
  request.source = Key("a", "in");
  request.destination = Key("b", "line");
  request.max_candidates = 1;

  const Planner planner;
  const PlanningResult result = planner.Plan(fabric.value(), request);
  std::cout << "outcome " << PlanOutcomeName(result.outcome) << "\n";
  if (result.outcome != PlanOutcome::Feasible) {
    std::cerr << result.ExplainText();
    return 1;
  }

  const PlanArtifact& plan = result.candidates.front();
  std::cout << "plan digest " << plan.DigestHex() << " cost " << plan.total_cost << " hops " << plan.hops
            << "\n";
  std::cout << "required spectrum:\n";
  for (const PlanReservation& reservation : plan.reservations) {
    std::cout << "  " << ResourceKeyToString(reservation.resource) << " slot "
              << reservation.channel.first_slot << "\n";
  }

  const ValidationReport validation = ValidatePlanBindings(plan, fabric.value());
  std::cout << "validation " << PlanValidityName(validation.validity) << "\n";
  if (validation.validity != PlanValidity::Valid) return 1;

  // The same artifact must be rejected once the evidence generation moves.
  const auto newer = BuildFabric(8);
  if (!newer.ok()) return 1;
  const ValidationReport replayed = ValidatePlanBindings(plan, newer.value());
  std::cout << "after a generation bump: " << PlanValidityName(replayed.validity) << "\n";
  if (replayed.validity != PlanValidity::Stale) {
    std::cerr << "a replayed plan was accepted against newer evidence\n";
    return 1;
  }

  // The sealed artifact round-trips through its canonical encoding.
  const auto reparsed = ParsePlanArtifact(plan.CanonicalBytes());
  if (!reparsed.ok() || !(reparsed.value().digest == plan.digest)) {
    std::cerr << "plan artifact did not round trip\n";
    return 1;
  }
  std::cout << "plan artifact round trip ok\n";
  return 0;
}
