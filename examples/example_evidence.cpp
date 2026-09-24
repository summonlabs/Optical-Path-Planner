// Evidence quality: the difference between INFEASIBLE and INDETERMINATE.
//
// Three snapshots describe the same shape. The first publishes everything, so a
// missing route is a proof. The second leaves one span quantity unpublished, so
// the same route becomes merely unprovable. The third contains two records that
// disagree about a span, which is CONFLICTING evidence.

#include <iostream>
#include <string>

#include "opp/opp.hpp"

namespace {

using namespace opp;

struct Fixture {
  Expected<TopologySnapshot> snapshot;
};

Expected<TopologySnapshot> Build(bool publish_osnr, bool conflicting_span) {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted(conflicting_span ? "conflicting" : "evidence"));
  builder.SetGeneration(1);
  SpectrumModel spectrum;
  spectrum.grid = GridKind::Fixed50GHz;
  spectrum.slot_count = 4;
  builder.SetSpectrum(spectrum);

  const SourceId source = SourceId::Trusted("evidence-source");
  SourceRecord source_record;
  source_record.id = source;
  source_record.generation = 1;
  Status status = builder.AddSource(source_record);
  if (status.failed()) return status;

  ReachProfile profile;
  profile.id = ProfileId::Trusted("p");
  profile.max_distance_m = Evidence<std::uint64_t>::Known(1000000);
  profile.max_span_count = Evidence<std::uint32_t>::Known(8);
  profile.max_loss_db = Evidence<double>::Known(100.0);
  profile.min_osnr_db = Evidence<double>::Known(10.0);
  profile.source = source;
  profile.generation = 1;
  status = builder.AddReachProfile(profile);
  if (status.failed()) return status;

  for (const char* name : {"a", "b"}) {
    NodeRecord node;
    node.id = NodeId::Trusted(name);
    node.kind = NodeKind::ReconfigurableOadm;
    node.admin = Evidence<AdminState>::Known(AdminState::Up);
    node.source = source;
    node.generation = 1;
    status = builder.AddNode(node);
    if (status.failed()) return status;
  }
  for (const char* name : {"a", "b"}) {
    for (const char* port : {"in", "out", "line"}) {
      PortRecord record;
      record.key.node = NodeId::Trusted(name);
      record.key.port = PortId::Trusted(port);
      record.role = std::string(port) == "line" ? PortRole::Line : PortRole::Client;
      record.admin = Evidence<AdminState>::Known(AdminState::Up);
      record.transmit_profile =
          Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(profile.id));
      record.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
      record.source = source;
      record.generation = 1;
      status = builder.AddPort(record);
      if (status.failed()) return status;
    }
  }
  for (const char* name : {"a", "b"}) {
    const char* other = std::string(name) == "a" ? "out" : "out";
    CrossConnectRecord record;
    record.id = CrossConnectId::Trusted(std::string("x-") + name);
    record.from = PortKey{NodeId::Trusted(name), PortId::Trusted("in")};
    record.to = PortKey{NodeId::Trusted(name), PortId::Trusted(other)};
    record.op = CrossConnectOp::Express;
    record.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
    record.admin = Evidence<AdminState>::Known(AdminState::Up);
    record.source = source;
    record.generation = 1;
    status = builder.AddCrossConnect(record);
    if (status.failed()) return status;
  }

  SpanRecord span;
  span.id = SpanId::Trusted("s");
  span.from = PortKey{NodeId::Trusted("a"), PortId::Trusted("out")};
  span.to = PortKey{NodeId::Trusted("b"), PortId::Trusted("in")};
  span.length_m = Evidence<std::uint64_t>::Known(1000);
  span.loss_db = Evidence<double>::Known(1.0);
  span.osnr_db = publish_osnr ? Evidence<double>::Known(30.0) : Evidence<double>::Unknown();
  span.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  span.admin = Evidence<AdminState>::Known(AdminState::Up);
  span.source = source;
  span.generation = 1;
  status = builder.AddSpan(span);
  if (status.failed()) return status;

  if (conflicting_span) {
    SpanRecord second = span;
    second.loss_db = Evidence<double>::Known(42.0);
    status = builder.AddSpan(second);
    if (status.failed()) return status;
  }

  // The only route must pass through the span, so the published state of that
  // span decides the outcome.
  SpanRecord away;
  away.id = SpanId::Trusted("unused");
  away.from = PortKey{NodeId::Trusted("a"), PortId::Trusted("line")};
  away.to = PortKey{NodeId::Trusted("b"), PortId::Trusted("line")};
  away.length_m = Evidence<std::uint64_t>::Known(1000);
  away.loss_db = Evidence<double>::Known(1.0);
  away.osnr_db = Evidence<double>::Known(30.0);
  away.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  away.admin = Evidence<AdminState>::Known(AdminState::Up);
  away.source = source;
  away.generation = 1;
  status = builder.AddSpan(away);
  if (status.failed()) return status;

  return builder.Build();
}

void Report(const char* label, const PlanningResult& result) {
  std::cout << label << ": " << PlanOutcomeName(result.outcome) << " limitations="
            << DescribeLimitations(result.limitations) << "\n";
  for (const Witness& witness : result.witnesses) {
    std::cout << "    witness " << CutReasonName(witness.reason) << " "
              << ResourceKeyToString(witness.resource) << " - " << witness.detail << "\n";
  }
}

}  // namespace

int main() {
  using namespace opp;

  PlanningRequest request;
  request.id = RequestId::Trusted("evidence");
  request.source = PortKey{NodeId::Trusted("a"), PortId::Trusted("in")};
  request.destination = PortKey{NodeId::Trusted("b"), PortId::Trusted("out")};

  const Planner planner;

  const auto complete = Build(true, false);
  if (!complete.ok()) {
    std::cerr << complete.status().detail << "\n";
    return 1;
  }
  Report("fully published", planner.Plan(complete.value(), request));

  const auto incomplete = Build(false, false);
  if (!incomplete.ok()) {
    std::cerr << incomplete.status().detail << "\n";
    return 1;
  }
  Report("span OSNR unpublished", planner.Plan(incomplete.value(), request));

  const auto conflicting = Build(true, true);
  if (!conflicting.ok()) {
    std::cerr << conflicting.status().detail << "\n";
    return 1;
  }
  std::cout << "conflicted resources: " << conflicting.value().conflicted_resources().size() << "\n";
  Report("disagreeing span records", planner.Plan(conflicting.value(), request));

  return 0;
}
