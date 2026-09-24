#include "test_support.hpp"

#include <algorithm>
#include <system_error>

namespace opp_test {

using namespace opp;

namespace {

std::string UniqueName(const std::string& name) {
  static std::uint32_t counter = 0;
  counter += 1;
  return name + "-" + std::to_string(static_cast<unsigned long long>(ProcessId())) + "-" +
         std::to_string(counter);
}

}  // namespace

std::uint64_t Random::Next() {
  state_ += 0x9E3779B97F4A7C15ull;
  std::uint64_t value = state_;
  value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
  value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
  return value ^ (value >> 31);
}

std::uint32_t Random::Below(std::uint32_t bound) {
  if (bound == 0) return 0;
  return static_cast<std::uint32_t>(Next() % bound);
}

double Random::UnitDouble() {
  return static_cast<double>(Next() >> 11) * (1.0 / 9007199254740992.0);
}

std::string FreshTempDir(const std::string& name) {
  const std::filesystem::path base = std::filesystem::temp_directory_path() / "opp-tests" / UniqueName(name);
  std::error_code error;
  std::filesystem::remove_all(base, error);
  std::filesystem::create_directories(base, error);
  return base.string();
}

void RemoveTree(const std::string& path) {
  std::error_code error;
  std::filesystem::remove_all(path, error);
}

Expected<TopologySnapshot> BuildCompleteSnapshot(std::uint64_t seed, std::uint32_t node_count,
                                                 std::uint16_t slot_count,
                                                 std::uint32_t slot_blocking_one_in) {
  SyntheticOptions options;
  options.seed = seed;
  options.node_count = node_count;
  options.degree = 3;
  options.slot_count = slot_count;
  options.client_ports = 2;
  options.slot_blocking_one_in = slot_blocking_one_in;
  options.include_regenerators = true;
  options.generation = 4;
  options.id = "fixture-" + std::to_string(seed);
  return GenerateSyntheticTopology(options);
}

Expected<TopologySnapshot> BuildSnapshotWithUnknownOsnr(std::uint64_t seed, std::uint32_t node_count) {
  SyntheticOptions options;
  options.seed = seed;
  options.node_count = node_count;
  options.degree = 3;
  options.slot_count = 8;
  options.slot_blocking_one_in = 0;
  options.publish_osnr = false;
  options.generation = 4;
  options.id = "fixture-unknown-" + std::to_string(seed);
  return GenerateSyntheticTopology(options);
}

Expected<TopologySnapshot> BuildPartialCoverageSnapshot() {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("partial"));
  builder.SetGeneration(2);
  SpectrumModel spectrum;
  spectrum.grid = GridKind::Fixed50GHz;
  spectrum.slot_count = 4;
  builder.SetSpectrum(spectrum);

  const SourceId source = SourceId::Trusted("partial-source");
  SourceRecord source_record;
  source_record.id = source;
  source_record.generation = 2;
  Status status = builder.AddSource(source_record);
  if (status.failed()) return status;

  ReachProfile profile;
  profile.id = ProfileId::Trusted("p");
  profile.max_distance_m = Evidence<std::uint64_t>::Known(1000000);
  profile.max_span_count = Evidence<std::uint32_t>::Known(16);
  profile.max_loss_db = Evidence<double>::Known(100.0);
  profile.min_osnr_db = Evidence<double>::Known(5.0);
  profile.source = source;
  profile.generation = 2;
  status = builder.AddReachProfile(profile);
  if (status.failed()) return status;

  for (const char* name : {"a", "b"}) {
    NodeRecord node;
    node.id = NodeId::Trusted(name);
    node.kind = NodeKind::ReconfigurableOadm;
    // The intermediate node does not publish its whole adjacency.
    node.coverage = std::string(name) == "b" ? Coverage::Partial : Coverage::Complete;
    node.admin = Evidence<AdminState>::Known(AdminState::Up);
    node.source = source;
    node.generation = 2;
    status = builder.AddNode(std::move(node));
    if (status.failed()) return status;
  }
  for (const char* name : {"a", "b"}) {
    for (const char* port : {"in", "out", "line"}) {
      PortRecord record;
      record.key.node = NodeId::Trusted(name);
      record.key.port = PortId::Trusted(port);
      record.role = std::string(port) == "line" ? PortRole::Line : PortRole::Client;
      record.admin = Evidence<AdminState>::Known(AdminState::Up);
      record.transmit_profile = Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(profile.id));
      record.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
      record.source = source;
      record.generation = 2;
      status = builder.AddPort(std::move(record));
      if (status.failed()) return status;
    }
    CrossConnectRecord cross_connect;
    cross_connect.id = CrossConnectId::Trusted(std::string("x-") + name);
    cross_connect.from = PortKey{NodeId::Trusted(name), PortId::Trusted("in")};
    cross_connect.to = PortKey{NodeId::Trusted(name), PortId::Trusted("out")};
    cross_connect.op = CrossConnectOp::Express;
    cross_connect.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
    cross_connect.admin = Evidence<AdminState>::Known(AdminState::Up);
    cross_connect.source = source;
    cross_connect.generation = 2;
    status = builder.AddCrossConnect(std::move(cross_connect));
    if (status.failed()) return status;
  }

  SpanRecord span;
  span.id = SpanId::Trusted("s");
  span.from = PortKey{NodeId::Trusted("a"), PortId::Trusted("out")};
  span.to = PortKey{NodeId::Trusted("b"), PortId::Trusted("line")};
  span.length_m = Evidence<std::uint64_t>::Known(1000);
  span.loss_db = Evidence<double>::Known(1.0);
  span.osnr_db = Evidence<double>::Known(30.0);
  span.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  span.admin = Evidence<AdminState>::Known(AdminState::Up);
  span.source = source;
  span.generation = 2;
  status = builder.AddSpan(std::move(span));
  if (status.failed()) return status;

  return builder.Build();
}

Expected<TopologySnapshot> BuildTwoNodeSnapshot(Evidence<double> span_osnr) {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("two-node"));
  builder.SetGeneration(1);
  SpectrumModel spectrum;
  spectrum.grid = GridKind::Fixed50GHz;
  spectrum.slot_count = 4;
  builder.SetSpectrum(spectrum);

  const SourceId source = SourceId::Trusted("two-node-source");
  SourceRecord source_record;
  source_record.id = source;
  source_record.generation = 1;
  Status status = builder.AddSource(source_record);
  if (status.failed()) return status;

  ReachProfile profile;
  profile.id = ProfileId::Trusted("p");
  profile.max_distance_m = Evidence<std::uint64_t>::Known(1000000);
  profile.max_span_count = Evidence<std::uint32_t>::Known(16);
  profile.max_loss_db = Evidence<double>::Known(100.0);
  profile.min_osnr_db = Evidence<double>::Known(5.0);
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
    status = builder.AddNode(std::move(node));
    if (status.failed()) return status;
    for (const char* port : {"in", "out"}) {
      PortRecord record;
      record.key.node = NodeId::Trusted(name);
      record.key.port = PortId::Trusted(port);
      record.role = PortRole::Client;
      record.admin = Evidence<AdminState>::Known(AdminState::Up);
      record.transmit_profile = Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(profile.id));
      record.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
      record.source = source;
      record.generation = 1;
      status = builder.AddPort(std::move(record));
      if (status.failed()) return status;
    }
    CrossConnectRecord cross_connect;
    cross_connect.id = CrossConnectId::Trusted(std::string("x-") + name);
    cross_connect.from = PortKey{NodeId::Trusted(name), PortId::Trusted("in")};
    cross_connect.to = PortKey{NodeId::Trusted(name), PortId::Trusted("out")};
    cross_connect.op = CrossConnectOp::Express;
    cross_connect.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
    cross_connect.admin = Evidence<AdminState>::Known(AdminState::Up);
    cross_connect.source = source;
    cross_connect.generation = 1;
    status = builder.AddCrossConnect(std::move(cross_connect));
    if (status.failed()) return status;
  }

  SpanRecord span;
  span.id = SpanId::Trusted("s");
  span.from = PortKey{NodeId::Trusted("a"), PortId::Trusted("out")};
  span.to = PortKey{NodeId::Trusted("b"), PortId::Trusted("in")};
  span.length_m = Evidence<std::uint64_t>::Known(1000);
  span.loss_db = Evidence<double>::Known(1.0);
  span.osnr_db = span_osnr;
  span.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  span.admin = Evidence<AdminState>::Known(AdminState::Up);
  span.source = source;
  span.generation = 1;
  status = builder.AddSpan(std::move(span));
  if (status.failed()) return status;

  return builder.Build();
}


Expected<TopologySnapshot> BuildChainSnapshot(std::uint32_t node_count, std::uint16_t slot_count, std::uint64_t seed,
                                              bool ring) {
  if (node_count < 2) return Failure(StatusCode::InvalidArgument, "a chain needs at least two nodes");

  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted(ring ? "ring-fixture" : "chain-fixture"));
  builder.SetGeneration(3);
  SpectrumModel spectrum;
  spectrum.grid = GridKind::Fixed50GHz;
  spectrum.slot_count = slot_count;
  builder.SetSpectrum(spectrum);

  const SourceId source = SourceId::Trusted("chain-source");
  SourceRecord source_record;
  source_record.id = source;
  source_record.generation = 3;
  Status status = builder.AddSource(source_record);
  if (status.failed()) return status;

  const ProfileId profile = ProfileId::Trusted("chain-reach");
  ReachProfile reach;
  reach.id = profile;
  reach.max_distance_m = Evidence<std::uint64_t>::Known(1200000);
  reach.max_span_count = Evidence<std::uint32_t>::Known(8);
  reach.max_loss_db = Evidence<double>::Known(120.0);
  reach.min_osnr_db = Evidence<double>::Known(12.0);
  reach.source = source;
  reach.generation = 3;
  status = builder.AddReachProfile(reach);
  if (status.failed()) return status;

  Random random(seed * 104729ull + node_count);

  const auto port_name = [](const char* name) { return PortId::Trusted(name); };

  for (std::uint32_t i = 0; i < node_count; ++i) {
    const bool regenerates = (i % 4u) == 3u;
    NodeRecord node;
    node.id = NodeId::Trusted("c" + std::to_string(i));
    node.kind = regenerates ? NodeKind::Regenerator : NodeKind::ReconfigurableOadm;
    node.failure_domains.push_back(FailureDomainId::Trusted("site" + std::to_string(i / 2u)));
    node.transit_cost = 1 + (i % 3u);
    node.coverage = Coverage::Complete;
    node.admin = Evidence<AdminState>::Known(AdminState::Up);
    node.source = source;
    node.generation = 3;
    status = builder.AddNode(std::move(node));
    if (status.failed()) return status;

    for (const char* name : {"in", "out", "w", "e"}) {
      const bool client = std::string(name) == "in" || std::string(name) == "out";
      PortRecord port;
      port.key = PortKey{NodeId::Trusted("c" + std::to_string(i)), port_name(name)};
      port.role = client ? PortRole::Client : PortRole::Line;
      port.admin = Evidence<AdminState>::Known(AdminState::Up);
      const bool has_transmitter = client || regenerates;
      port.transmit_profile = has_transmitter
                                  ? Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(profile))
                                  : Evidence<std::optional<ProfileId>>::Known(std::nullopt);
      port.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
      port.failure_domains.push_back(FailureDomainId::Trusted("rack" + std::to_string(i / 2u)));
      port.transit_cost = 1;
      port.source = source;
      port.generation = 3;
      status = builder.AddPort(std::move(port));
      if (status.failed()) return status;
    }

    // Node 0 has no western neighbour in a chain, and the last node has no
    // eastern one; a ring closes both ends.
    const bool has_west = i > 0 || ring;
    const bool has_east = i + 1 < node_count || ring;
    std::vector<std::pair<const char*, const char*>> links = {
        {"in", "e"}, {"in", "w"}, {"e", "out"}, {"w", "out"}, {"w", "e"}, {"e", "w"}};
    std::uint32_t counter = 0;
    for (const auto& link : links) {
      const std::string from(link.first);
      const std::string to(link.second);
      if ((from == "w" || to == "w") && !has_west) continue;
      if ((from == "e" || to == "e") && !has_east) continue;
      CrossConnectRecord record;
      record.id = CrossConnectId::Trusted("cx" + std::to_string(i) + "-" + std::to_string(counter++));
      record.from = PortKey{NodeId::Trusted("c" + std::to_string(i)), port_name(link.first)};
      record.to = PortKey{NodeId::Trusted("c" + std::to_string(i)), port_name(link.second)};
      const bool through_line = from != "in" && to != "out";
      record.op = (regenerates && through_line) ? CrossConnectOp::Regenerate : CrossConnectOp::Express;
      record.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
      record.admin = Evidence<AdminState>::Known(AdminState::Up);
      record.failure_domains.push_back(FailureDomainId::Trusted("rack" + std::to_string(i / 2u)));
      record.cost = 1;
      record.source = source;
      record.generation = 3;
      status = builder.AddCrossConnect(std::move(record));
      if (status.failed()) return status;
    }
  }

  const auto add_span = [&](std::uint32_t left, std::uint32_t right) -> Status {
    const std::uint64_t length_m = 30000ull + random.Below(70000);
    SlotMask blocked;
    for (std::uint16_t slot = 0; slot < slot_count; ++slot) {
      if ((random.Next() % 5u) == 0) blocked.Set(slot);
    }
    SpanRecord span;
    span.id = SpanId::Trusted("sp" + std::to_string(left) + "-" + std::to_string(right));
    span.from = PortKey{NodeId::Trusted("c" + std::to_string(left)), port_name("e")};
    span.to = PortKey{NodeId::Trusted("c" + std::to_string(right)), port_name("w")};
    span.bidirectional = true;
    span.length_m = Evidence<std::uint64_t>::Known(length_m);
    span.loss_db = Evidence<double>::Known(static_cast<double>(length_m) * 0.0002);
    span.osnr_db = Evidence<double>::Known(26.0 + random.UnitDouble() * 8.0);
    span.blocked_slots = Evidence<SlotMask>::Known(blocked);
    span.failure_domains.push_back(
        FailureDomainId::Trusted("fiber" + std::to_string(left) + "-" + std::to_string(right)));
    span.admin = Evidence<AdminState>::Known(AdminState::Up);
    span.cost = 1 + random.Below(4);
    span.source = source;
    span.generation = 3;
    return builder.AddSpan(std::move(span));
  };

  for (std::uint32_t i = 0; i + 1 < node_count; ++i) {
    status = add_span(i, i + 1);
    if (status.failed()) return status;
  }
  if (ring && node_count > 2) {
    status = add_span(node_count - 1, 0);
    if (status.failed()) return status;
  }

  return builder.Build();
}

}  // namespace opp_test
