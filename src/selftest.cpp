#include "opp/opp.hpp"

#include <cmath>
#include <string>
#include <vector>

#include "opp/canonical.hpp"
#include "opp/sha256.hpp"
#include "opp/snapshot_io.hpp"

namespace opp {
namespace {

Status Check(bool condition, const std::string& detail) {
  return condition ? OkStatus() : Failure(StatusCode::IntegrityFailure, detail);
}

Status CheckTokenRoundTrip(std::string_view raw) {
  const std::string encoded = EncodeToken(raw);
  if (!IsSafeToken(encoded)) {
    return Failure(StatusCode::IntegrityFailure, "encoded token is not a safe token");
  }
  const auto decoded = DecodeToken(encoded);
  if (!decoded.ok()) return decoded.status();
  if (decoded.value() != raw) {
    return Failure(StatusCode::IntegrityFailure, "token round trip changed the value");
  }
  if (EncodeToken(decoded.value()) != encoded) {
    return Failure(StatusCode::IntegrityFailure, "token encoding is not canonical");
  }
  return OkStatus();
}

Status CheckDoubleRoundTrip(double value) {
  const auto text = FormatDouble(value);
  if (!text.ok()) return text.status();
  const auto parsed = ParseDouble(text.value());
  if (!parsed.ok()) return parsed.status();
  if (!(parsed.value() == value)) {
    return Failure(StatusCode::IntegrityFailure, "double round trip changed the value");
  }
  return OkStatus();
}

Status CheckSpectrumRules() {
  const SlotMask all = SlotMask::All(16);
  if (all.Count() != 16) {
    return Failure(StatusCode::IntegrityFailure, "SlotMask::All did not set every slot");
  }
  SlotMask trimmed = all;
  trimmed.Reset(3);
  const SlotMask first = trimmed.FirstSlotMask(2);
  if (first.Test(2) || first.Test(3) || !first.Test(1) || !first.Test(4)) {
    return Failure(StatusCode::IntegrityFailure, "FirstSlotMask did not account for a blocked slot");
  }
  const auto lowest = first.LowestSetBit();
  if (!lowest.has_value() || lowest.value() != 0) {
    return Failure(StatusCode::IntegrityFailure, "LowestSetBit did not return the first usable slot");
  }
  const auto hex = all.ToHex();
  const auto parsed = SlotMask::FromHex(hex);
  if (!parsed.ok() || !(parsed.value() == all)) {
    return Failure(StatusCode::IntegrityFailure, "slot mask hex round trip failed");
  }
  const SlotMask empty = SlotMask::None();
  if (!empty.IsEmpty() || empty.LowestSetBit().has_value()) {
    return Failure(StatusCode::IntegrityFailure, "an empty slot mask reported a usable slot");
  }
  if (!empty.FirstSlotMask(1).IsEmpty()) {
    return Failure(StatusCode::IntegrityFailure, "an empty slot mask produced channel starts");
  }
  return OkStatus();
}

Status CheckCheckedArithmetic() {
  std::uint64_t out = 0;
  if (!AddCheckedU64(1, 2, &out) || out != 3) {
    return Failure(StatusCode::IntegrityFailure, "AddCheckedU64 rejected a representable sum");
  }
  if (AddCheckedU64(UINT64_MAX, 1, &out)) {
    return Failure(StatusCode::IntegrityFailure, "AddCheckedU64 accepted an overflow");
  }
  if (!MulCheckedU64(4, 5, &out) || out != 20) {
    return Failure(StatusCode::IntegrityFailure, "MulCheckedU64 rejected a representable product");
  }
  if (MulCheckedU64(UINT64_MAX, 2, &out)) {
    return Failure(StatusCode::IntegrityFailure, "MulCheckedU64 accepted an overflow");
  }
  return OkStatus();
}

Status CheckSnapshotRoundTrip() {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("selftest"));
  builder.SetGeneration(7);
  SpectrumModel spectrum;
  spectrum.grid = GridKind::Flex12_5GHz;
  spectrum.slot_count = 8;
  builder.SetSpectrum(spectrum);

  SourceRecord source;
  source.id = SourceId::Trusted("synthetic");
  source.generation = 3;
  Status status = builder.AddSource(source);
  if (status.failed()) return status;

  ReachProfile profile;
  profile.id = ProfileId::Trusted("p1");
  profile.max_distance_m = Evidence<std::uint64_t>::Known(100000);
  profile.max_span_count = Evidence<std::uint32_t>::Known(4);
  profile.max_loss_db = Evidence<double>::Known(20.0);
  profile.min_osnr_db = Evidence<double>::Known(12.5);
  profile.source = source.id;
  profile.generation = 3;
  status = builder.AddReachProfile(profile);
  if (status.failed()) return status;

  for (const char* name : {"a", "b"}) {
    NodeRecord node;
    node.id = NodeId::Trusted(name);
    node.kind = NodeKind::ReconfigurableOadm;
    node.admin = Evidence<AdminState>::Known(AdminState::Up);
    node.source = source.id;
    node.generation = 3;
    status = builder.AddNode(node);
    if (status.failed()) return status;
  }
  for (const char* port : {"in", "out"}) {
    PortRecord record;
    record.key.node = NodeId::Trusted("a");
    record.key.port = PortId::Trusted(port);
    record.role = PortRole::Line;
    record.admin = Evidence<AdminState>::Known(AdminState::Up);
    record.transmit_profile = Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(profile.id));
    record.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
    record.source = source.id;
    record.generation = 3;
    status = builder.AddPort(record);
    if (status.failed()) return status;
  }
  for (const char* port : {"in", "out"}) {
    PortRecord record;
    record.key.node = NodeId::Trusted("b");
    record.key.port = PortId::Trusted(port);
    record.role = PortRole::Line;
    record.admin = Evidence<AdminState>::Known(AdminState::Up);
    record.transmit_profile = Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(profile.id));
    record.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
    record.source = source.id;
    record.generation = 3;
    status = builder.AddPort(record);
    if (status.failed()) return status;
  }

  SpanRecord span;
  span.id = SpanId::Trusted("s1");
  span.from = PortKey{NodeId::Trusted("a"), PortId::Trusted("out")};
  span.to = PortKey{NodeId::Trusted("b"), PortId::Trusted("in")};
  span.length_m = Evidence<std::uint64_t>::Known(1000);
  span.loss_db = Evidence<double>::Known(1.5);
  span.osnr_db = Evidence<double>::Known(30.0);
  span.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  span.admin = Evidence<AdminState>::Known(AdminState::Up);
  span.source = source.id;
  span.generation = 3;
  status = builder.AddSpan(span);
  if (status.failed()) return status;

  CrossConnectRecord cross_connect;
  cross_connect.id = CrossConnectId::Trusted("x1");
  cross_connect.from = PortKey{NodeId::Trusted("a"), PortId::Trusted("in")};
  cross_connect.to = PortKey{NodeId::Trusted("a"), PortId::Trusted("out")};
  cross_connect.op = CrossConnectOp::Express;
  cross_connect.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  cross_connect.admin = Evidence<AdminState>::Known(AdminState::Up);
  cross_connect.source = source.id;
  cross_connect.generation = 3;
  status = builder.AddCrossConnect(cross_connect);
  if (status.failed()) return status;

  const auto built = builder.Build();
  if (!built.ok()) return built.status();
  const TopologySnapshot& snapshot = built.value();

  const std::string text = SnapshotToText(snapshot);
  const auto reparsed = ParseSnapshotText(text);
  if (!reparsed.ok()) return reparsed.status();
  if (!(reparsed.value().digest() == snapshot.digest())) {
    return Failure(StatusCode::IntegrityFailure, "snapshot digest is not stable across a text round trip");
  }
  if (SnapshotToText(reparsed.value()) != text) {
    return Failure(StatusCode::IntegrityFailure, "snapshot text encoding is not canonical");
  }
  if (!snapshot.coverage_complete()) {
    return Failure(StatusCode::IntegrityFailure, "a fully published snapshot was reported as partial coverage");
  }
  return OkStatus();
}

Status CheckPlanRoundTrip() {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("selftest-plan"));
  builder.SetGeneration(1);
  SpectrumModel spectrum;
  spectrum.grid = GridKind::Fixed50GHz;
  spectrum.slot_count = 4;
  builder.SetSpectrum(spectrum);

  SourceRecord source;
  source.id = SourceId::Trusted("synthetic");
  source.generation = 1;
  Status status = builder.AddSource(source);
  if (status.failed()) return status;

  ReachProfile profile;
  profile.id = ProfileId::Trusted("p1");
  profile.max_distance_m = Evidence<std::uint64_t>::Known(100000);
  profile.max_span_count = Evidence<std::uint32_t>::Known(4);
  profile.max_loss_db = Evidence<double>::Known(20.0);
  profile.min_osnr_db = Evidence<double>::Known(10.0);
  profile.source = source.id;
  profile.generation = 1;
  status = builder.AddReachProfile(profile);
  if (status.failed()) return status;

  for (const char* name : {"a", "b"}) {
    NodeRecord node;
    node.id = NodeId::Trusted(name);
    node.kind = NodeKind::Terminal;
    node.admin = Evidence<AdminState>::Known(AdminState::Up);
    node.source = source.id;
    node.generation = 1;
    status = builder.AddNode(node);
    if (status.failed()) return status;
  }
  for (const char* port : {"in", "out"}) {
    for (const char* node : {"a", "b"}) {
      PortRecord record;
      record.key.node = NodeId::Trusted(node);
      record.key.port = PortId::Trusted(port);
      record.role = PortRole::Client;
      record.admin = Evidence<AdminState>::Known(AdminState::Up);
      record.transmit_profile = Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(profile.id));
      record.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
      record.source = source.id;
      record.generation = 1;
      status = builder.AddPort(record);
      if (status.failed()) return status;
    }
  }
  SpanRecord span;
  span.id = SpanId::Trusted("s1");
  span.from = PortKey{NodeId::Trusted("a"), PortId::Trusted("out")};
  span.to = PortKey{NodeId::Trusted("b"), PortId::Trusted("in")};
  span.length_m = Evidence<std::uint64_t>::Known(1000);
  span.loss_db = Evidence<double>::Known(2.0);
  span.osnr_db = Evidence<double>::Known(28.0);
  span.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  span.admin = Evidence<AdminState>::Known(AdminState::Up);
  span.source = source.id;
  span.generation = 1;
  status = builder.AddSpan(span);
  if (status.failed()) return status;

  CrossConnectRecord cross_connect;
  cross_connect.id = CrossConnectId::Trusted("x1");
  cross_connect.from = PortKey{NodeId::Trusted("a"), PortId::Trusted("in")};
  cross_connect.to = PortKey{NodeId::Trusted("a"), PortId::Trusted("out")};
  cross_connect.op = CrossConnectOp::Express;
  cross_connect.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  cross_connect.admin = Evidence<AdminState>::Known(AdminState::Up);
  cross_connect.source = source.id;
  cross_connect.generation = 1;
  status = builder.AddCrossConnect(cross_connect);
  if (status.failed()) return status;

  const auto built = builder.Build();
  if (!built.ok()) return built.status();

  PlanningRequest request;
  request.id = RequestId::Trusted("selftest");
  request.source = PortKey{NodeId::Trusted("a"), PortId::Trusted("in")};
  request.destination = PortKey{NodeId::Trusted("b"), PortId::Trusted("in")};
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  if (result.outcome != PlanOutcome::Feasible) {
    return Failure(StatusCode::IntegrityFailure,
                   std::string("self test plan did not succeed: ") + PlanOutcomeName(result.outcome));
  }
  const PlanArtifact& plan = result.candidates.front();
  const auto reparsed = ParsePlanArtifact(plan.CanonicalBytes());
  if (!reparsed.ok()) return reparsed.status();
  if (!(reparsed.value().digest == plan.digest)) {
    return Failure(StatusCode::IntegrityFailure, "plan digest is not stable across a text round trip");
  }
  const auto result_reparsed = ParseResultText(result.CanonicalBytes());
  if (!result_reparsed.ok()) return result_reparsed.status();
  if (!(result_reparsed.value().result_digest == result.result_digest)) {
    return Failure(StatusCode::IntegrityFailure, "result digest is not stable across a text round trip");
  }
  return OkStatus();
}

}  // namespace

Status SelfTest() {
  std::string detail;
  if (!Sha256SelfTest(&detail)) {
    return Failure(StatusCode::IntegrityFailure, detail);
  }
  Status status = CheckCheckedArithmetic();
  if (status.failed()) return status;

  const char* const tokens[] = {"plain", "with space", "with\ttab", "", "unicode-\xc3\xa9", "percent%20"};
  for (const char* token : tokens) {
    status = CheckTokenRoundTrip(token);
    if (status.failed()) return status;
  }

  const double doubles[] = {0.0, -0.0, 1.5, -12.25, 1e-9, 1e12, 0.1, 3.14159265358979};
  for (double value : doubles) {
    status = CheckDoubleRoundTrip(value);
    if (status.failed()) return status;
  }

  status = CheckSpectrumRules();
  if (status.failed()) return status;
  status = CheckSnapshotRoundTrip();
  if (status.failed()) return status;
  status = CheckPlanRoundTrip();
  if (status.failed()) return status;

  Status ok = OkStatus();
  ok.detail = "digests, canonical codecs, spectrum rules, snapshot round trip and plan round trip all reproduce";
  return ok;
}

}  // namespace opp
