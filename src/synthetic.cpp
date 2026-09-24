#include "opp/synthetic.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "opp/canonical.hpp"
#include "opp/limits.hpp"

namespace opp {
namespace {

// splitmix64: a small, well distributed, fully specified generator. Reproducing
// its output needs no library support beyond unsigned 64-bit arithmetic.
class SplitMix64 {
 public:
  explicit SplitMix64(std::uint64_t seed) : state_(seed) {}

  std::uint64_t Next() {
    state_ += 0x9E3779B97F4A7C15ull;
    std::uint64_t value = state_;
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
    return value ^ (value >> 31);
  }

  std::uint32_t Below(std::uint32_t bound) {
    if (bound == 0) return 0;
    return static_cast<std::uint32_t>(Next() % bound);
  }

  double UnitDouble() { return static_cast<double>(Next() >> 11) * (1.0 / 9007199254740992.0); }

 private:
  std::uint64_t state_;
};

std::string Numbered(const char* prefix, std::uint32_t index) {
  return std::string(prefix) + std::to_string(index);
}

}  // namespace

Expected<TopologySnapshot> GenerateSyntheticTopology(const SyntheticOptions& options) {
  if (options.node_count < 2) {
    return Failure(StatusCode::InvalidArgument, "a synthetic topology needs at least two nodes");
  }
  if (options.node_count > kMaxGeneratedNodes) {
    return Failure(StatusCode::LimitExceeded, "the requested synthetic topology exceeds the node bound");
  }
  if (options.degree < 2) {
    return Failure(StatusCode::InvalidArgument, "a synthetic topology needs a degree of at least two");
  }
  if (options.degree >= options.node_count) {
    return Failure(StatusCode::InvalidArgument, "the requested degree is too large for the requested node count");
  }
  if (options.slot_count == 0 || options.slot_count > kMaxSpectrumSlots) {
    return Failure(StatusCode::InvalidArgument, "the requested slot count is outside the supported range");
  }
  if (options.client_ports == 0) {
    return Failure(StatusCode::InvalidArgument, "a synthetic topology needs at least one client port per node");
  }

  SplitMix64 random(options.seed);

  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Parse(options.id).ok() ? SnapshotId::Parse(options.id).value()
                                                   : SnapshotId::Trusted("synthetic"));
  builder.SetGeneration(options.generation);
  SpectrumModel spectrum;
  spectrum.grid = options.grid;
  spectrum.slot_count = options.slot_count;
  builder.SetSpectrum(spectrum);

  const SourceId source = SourceId::Trusted("synthetic-generator");
  SourceRecord source_record;
  source_record.id = source;
  source_record.generation = options.generation;
  source_record.coverage = Coverage::Complete;
  Status status = builder.AddSource(source_record);
  if (status.failed()) return status;

  // One shared reach profile keeps the fixture readable; it is still synthetic.
  const ProfileId profile = ProfileId::Trusted("reach-synthetic");
  ReachProfile profile_record;
  profile_record.id = profile;
  profile_record.max_distance_m = Evidence<std::uint64_t>::Known(800000);
  profile_record.max_span_count = Evidence<std::uint32_t>::Known(8);
  profile_record.max_loss_db = Evidence<double>::Known(60.0);
  profile_record.min_osnr_db = Evidence<double>::Known(12.0);
  profile_record.source = source;
  profile_record.generation = options.generation;
  status = builder.AddReachProfile(profile_record);
  if (status.failed()) return status;

  // ---- graph ---------------------------------------------------------------
  std::vector<std::pair<std::uint32_t, std::uint32_t>> edges;
  const auto add_edge = [&edges](std::uint32_t lhs, std::uint32_t rhs) {
    const std::uint32_t low = std::min(lhs, rhs);
    const std::uint32_t high = std::max(lhs, rhs);
    const std::pair<std::uint32_t, std::uint32_t> edge{low, high};
    if (std::find(edges.begin(), edges.end(), edge) == edges.end()) edges.push_back(edge);
  };
  for (std::uint32_t i = 0; i < options.node_count; ++i) {
    add_edge(i, (i + 1) % options.node_count);
  }
  const std::uint32_t stride = std::max<std::uint32_t>(2, options.node_count / std::max<std::uint32_t>(2, options.degree));
  for (std::uint32_t hop = 0; hop < options.degree; ++hop) {
    for (std::uint32_t i = 0; i < options.node_count; ++i) {
      const std::uint32_t target = (i + stride * (hop + 1)) % options.node_count;
      if (target != i) add_edge(i, target);
    }
  }
  std::sort(edges.begin(), edges.end());

  std::vector<std::vector<std::uint32_t>> neighbours(options.node_count);
  for (const auto& edge : edges) {
    neighbours[edge.first].push_back(edge.second);
    neighbours[edge.second].push_back(edge.first);
  }

  const auto is_regenerator = [&options](std::uint32_t index) {
    return options.include_regenerators && (index % 5u) == 4u;
  };

  for (std::uint32_t i = 0; i < options.node_count; ++i) {
    NodeRecord node;
    node.id = NodeId::Trusted(Numbered("n", i));
    node.kind = is_regenerator(i) ? NodeKind::Regenerator : NodeKind::ReconfigurableOadm;
    node.failure_domains.push_back(FailureDomainId::Trusted(Numbered("site", i / 4u)));
    node.failure_domains.push_back(FailureDomainId::Trusted(Numbered("rack", i / 2u)));
    node.transit_cost = 1;
    node.coverage = Coverage::Complete;
    node.admin = Evidence<AdminState>::Known(AdminState::Up);
    node.source = source;
    node.generation = options.generation;
    status = builder.AddNode(std::move(node));
    if (status.failed()) return status;

    for (std::uint32_t client = 0; client < options.client_ports; ++client) {
      PortRecord port;
      port.key.node = NodeId::Trusted(Numbered("n", i));
      port.key.port = PortId::Trusted(Numbered("c", client));
      port.role = PortRole::Client;
      port.admin = Evidence<AdminState>::Known(AdminState::Up);
      port.transmit_profile =
          Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(profile));
      port.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
      port.failure_domains.push_back(FailureDomainId::Trusted(Numbered("rack", i / 2u)));
      port.transit_cost = 1;
      port.source = source;
      port.generation = options.generation;
      status = builder.AddPort(std::move(port));
      if (status.failed()) return status;
    }

    for (std::uint32_t neighbour : neighbours[i]) {
      PortRecord port;
      port.key.node = NodeId::Trusted(Numbered("n", i));
      port.key.port = PortId::Trusted(Numbered("l", neighbour));
      port.role = PortRole::Line;
      port.admin = Evidence<AdminState>::Known(AdminState::Up);
      port.transmit_profile = is_regenerator(i)
                                  ? Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(profile))
                                  : Evidence<std::optional<ProfileId>>::Known(std::nullopt);
      port.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
      port.failure_domains.push_back(FailureDomainId::Trusted(Numbered("rack", i / 2u)));
      port.transit_cost = 1;
      port.source = source;
      port.generation = options.generation;
      status = builder.AddPort(std::move(port));
      if (status.failed()) return status;
    }
  }

  // ---- cross-connects ------------------------------------------------------
  for (std::uint32_t i = 0; i < options.node_count; ++i) {
    std::uint32_t counter = 0;
    const auto add_cross_connect = [&](const PortId& from, const PortId& to, CrossConnectOp op) -> Status {
      CrossConnectRecord record;
      record.id = CrossConnectId::Trusted(Numbered("xc", i * 1000u + counter));
      ++counter;
      record.from = PortKey{NodeId::Trusted(Numbered("n", i)), from};
      record.to = PortKey{NodeId::Trusted(Numbered("n", i)), to};
      record.op = op;
      record.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
      record.admin = Evidence<AdminState>::Known(AdminState::Up);
      record.failure_domains.push_back(FailureDomainId::Trusted(Numbered("rack", i / 2u)));
      record.cost = 1;
      record.source = source;
      record.generation = options.generation;
      return builder.AddCrossConnect(std::move(record));
    };

    for (std::uint32_t client = 0; client < options.client_ports; ++client) {
      for (std::uint32_t neighbour : neighbours[i]) {
        status = add_cross_connect(PortId::Trusted(Numbered("c", client)),
                                   PortId::Trusted(Numbered("l", neighbour)), CrossConnectOp::Express);
        if (status.failed()) return status;
        status = add_cross_connect(PortId::Trusted(Numbered("l", neighbour)),
                                   PortId::Trusted(Numbered("c", client)), CrossConnectOp::Express);
        if (status.failed()) return status;
      }
    }
    for (std::uint32_t from_neighbour : neighbours[i]) {
      for (std::uint32_t to_neighbour : neighbours[i]) {
        if (from_neighbour == to_neighbour) continue;
        const CrossConnectOp op = is_regenerator(i) ? CrossConnectOp::Regenerate : CrossConnectOp::Express;
        status = add_cross_connect(PortId::Trusted(Numbered("l", from_neighbour)),
                                   PortId::Trusted(Numbered("l", to_neighbour)), op);
        if (status.failed()) return status;
      }
    }
  }

  // ---- spans ---------------------------------------------------------------
  for (const auto& edge : edges) {
    SplitMix64 span_random(options.seed * 1000003ull + static_cast<std::uint64_t>(edge.first) * 1009ull +
                           static_cast<std::uint64_t>(edge.second));
    const std::uint64_t length_m = 20000ull + span_random.Below(100000);
    SpanRecord span;
    span.id = SpanId::Trusted("s" + std::to_string(edge.first) + "-" + std::to_string(edge.second));
    span.from = PortKey{NodeId::Trusted(Numbered("n", edge.first)), PortId::Trusted(Numbered("l", edge.second))};
    span.to = PortKey{NodeId::Trusted(Numbered("n", edge.second)), PortId::Trusted(Numbered("l", edge.first))};
    span.bidirectional = true;
    span.length_m = options.publish_length ? Evidence<std::uint64_t>::Known(length_m)
                                           : Evidence<std::uint64_t>::Unknown();
    span.loss_db = Evidence<double>::Known(static_cast<double>(length_m) * 0.0002);
    span.osnr_db = options.publish_osnr ? Evidence<double>::Known(26.0 + span_random.UnitDouble() * 8.0)
                                        : Evidence<double>::Unknown();
    SlotMask blocked;
    if (options.slot_blocking_one_in > 0) {
      for (std::uint16_t slot = 0; slot < options.slot_count; ++slot) {
        const std::uint64_t mixed = span_random.Next() ^ (static_cast<std::uint64_t>(slot) * 0x9E3779B97F4A7C15ull);
        if ((mixed % options.slot_blocking_one_in) == 0) blocked.Set(slot);
      }
    }
    span.blocked_slots = Evidence<SlotMask>::Known(blocked);
    span.failure_domains.push_back(
        FailureDomainId::Trusted("span" + std::to_string(edge.first) + "-" + std::to_string(edge.second)));
    span.admin = Evidence<AdminState>::Known(AdminState::Up);
    span.cost = 1 + (span_random.Below(3));
    span.source = source;
    span.generation = options.generation;
    status = builder.AddSpan(std::move(span));
    if (status.failed()) return status;
  }

  return builder.Build();
}

Expected<TopologySnapshot> BuildExampleTopology() {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("example"));
  builder.SetGeneration(42);
  SpectrumModel spectrum;
  spectrum.grid = GridKind::Fixed50GHz;
  spectrum.slot_count = 8;
  builder.SetSpectrum(spectrum);

  const SourceId source = SourceId::Trusted("example-evidence");
  SourceRecord source_record;
  source_record.id = source;
  source_record.generation = 7;
  source_record.coverage = Coverage::Complete;
  Status status = builder.AddSource(source_record);
  if (status.failed()) return status;

  const ProfileId profile = ProfileId::Trusted("reach-400km");
  ReachProfile profile_record;
  profile_record.id = profile;
  profile_record.max_distance_m = Evidence<std::uint64_t>::Known(400000);
  profile_record.max_span_count = Evidence<std::uint32_t>::Known(4);
  profile_record.max_loss_db = Evidence<double>::Known(30.0);
  profile_record.min_osnr_db = Evidence<double>::Known(14.0);
  profile_record.source = source;
  profile_record.generation = 7;
  status = builder.AddReachProfile(profile_record);
  if (status.failed()) return status;

  const char* const nodes[] = {"a", "b", "c"};
  for (std::size_t i = 0; i < 3; ++i) {
    NodeRecord node;
    node.id = NodeId::Trusted(nodes[i]);
    node.kind = NodeKind::ReconfigurableOadm;
    node.failure_domains.push_back(FailureDomainId::Trusted(i == 1 ? "site-b" : "site-a"));
    node.transit_cost = 1;
    node.admin = Evidence<AdminState>::Known(AdminState::Up);
    node.source = source;
    node.generation = 7;
    status = builder.AddNode(std::move(node));
    if (status.failed()) return status;
  }

  for (std::size_t i = 0; i < 3; ++i) {
    for (const char* port_name : {"in", "out", "east", "west"}) {
      PortRecord port;
      port.key.node = NodeId::Trusted(nodes[i]);
      port.key.port = PortId::Trusted(port_name);
      const bool client = std::string(port_name) == "in" || std::string(port_name) == "out";
      port.role = client ? PortRole::Client : PortRole::Line;
      port.admin = Evidence<AdminState>::Known(AdminState::Up);
      port.transmit_profile = client ? Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(profile))
                                     : Evidence<std::optional<ProfileId>>::Known(std::nullopt);
      port.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
      port.failure_domains.push_back(FailureDomainId::Trusted(i == 1 ? "site-b" : "site-a"));
      port.transit_cost = 1;
      port.source = source;
      port.generation = 7;
      status = builder.AddPort(std::move(port));
      if (status.failed()) return status;
    }
  }

  struct CrossConnectSpec {
    const char* id;
    const char* node;
    const char* from;
    const char* to;
    CrossConnectOp op;
  };
  const CrossConnectSpec cross_connects[] = {
      {"xa1", "a", "in", "east", CrossConnectOp::Express},
      {"xa2", "a", "in", "west", CrossConnectOp::Express},
      {"xa3", "a", "west", "out", CrossConnectOp::Express},
      {"xb1", "b", "west", "east", CrossConnectOp::Express},
      {"xb2", "b", "east", "west", CrossConnectOp::Express},
      {"xb3", "b", "west", "out", CrossConnectOp::Express},
      {"xc1", "c", "west", "out", CrossConnectOp::Express},
      {"xc2", "c", "east", "out", CrossConnectOp::Express},
  };
  for (const CrossConnectSpec& spec : cross_connects) {
    CrossConnectRecord record;
    record.id = CrossConnectId::Trusted(spec.id);
    record.from = PortKey{NodeId::Trusted(spec.node), PortId::Trusted(spec.from)};
    record.to = PortKey{NodeId::Trusted(spec.node), PortId::Trusted(spec.to)};
    record.op = spec.op;
    record.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
    record.admin = Evidence<AdminState>::Known(AdminState::Up);
    record.cost = 1;
    record.source = source;
    record.generation = 7;
    status = builder.AddCrossConnect(std::move(record));
    if (status.failed()) return status;
  }

  struct SpanSpec {
    const char* id;
    const char* from_node;
    const char* from_port;
    const char* to_node;
    const char* to_port;
    std::uint64_t length_m;
    double loss_db;
    double osnr_db;
    const char* domain;
    std::uint64_t cost;
  };
  const SpanSpec spans[] = {
      {"s-ab", "a", "east", "b", "west", 80000, 12.0, 30.0, "span-ab", 3},
      {"s-bc", "b", "east", "c", "west", 120000, 14.0, 28.0, "span-bc", 4},
      {"s-ac", "a", "west", "c", "east", 260000, 40.0, 22.0, "span-ac", 2},
  };
  for (const SpanSpec& spec : spans) {
    SpanRecord record;
    record.id = SpanId::Trusted(spec.id);
    record.from = PortKey{NodeId::Trusted(spec.from_node), PortId::Trusted(spec.from_port)};
    record.to = PortKey{NodeId::Trusted(spec.to_node), PortId::Trusted(spec.to_port)};
    record.bidirectional = true;
    record.length_m = Evidence<std::uint64_t>::Known(spec.length_m);
    record.loss_db = Evidence<double>::Known(spec.loss_db);
    record.osnr_db = Evidence<double>::Known(spec.osnr_db);
    record.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
    record.failure_domains.push_back(FailureDomainId::Trusted(spec.domain));
    record.admin = Evidence<AdminState>::Known(AdminState::Up);
    record.cost = spec.cost;
    record.source = source;
    record.generation = 7;
    status = builder.AddSpan(std::move(record));
    if (status.failed()) return status;
  }

  return builder.Build();
}

}  // namespace opp
