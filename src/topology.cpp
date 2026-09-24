#include "opp/topology.hpp"

#include <algorithm>
#include <cmath>
#include <string>
#include <utility>

#include "opp/canonical.hpp"
#include "opp/snapshot_io.hpp"

namespace opp {
namespace {

const std::vector<SpanArc>& EmptyArcs() {
  static const std::vector<SpanArc> kEmpty;
  return kEmpty;
}

const std::vector<std::uint32_t>& EmptyCrossConnects() {
  static const std::vector<std::uint32_t> kEmpty;
  return kEmpty;
}

Status ValidateFiniteNonNegative(const Evidence<double>& value, const char* field, double maximum) {
  if (!value.HasValue()) return OkStatus();
  const double raw = value.value();
  if (!std::isfinite(raw) || raw < 0.0 || raw > maximum) {
    return Failure(StatusCode::MalformedInput,
                   std::string(field) + " must be a finite value in [0, " + std::to_string(maximum) + "]");
  }
  return OkStatus();
}

template <class Record>
Status NormaliseDomains(std::vector<Record>& records, const char* what) {
  for (Record& record : records) {
    std::vector<FailureDomainId>& domains = record.failure_domains;
    std::sort(domains.begin(), domains.end());
    domains.erase(std::unique(domains.begin(), domains.end()), domains.end());
    if (domains.size() > kMaxDomainsPerResource) {
      return Failure(StatusCode::LimitExceeded,
                     std::string(what) + " declares more failure domains than the supported maximum");
    }
  }
  return OkStatus();
}

// Sorts records into canonical order, collapses byte-identical duplicates and
// records the identity of every record that disagreed with a duplicate. The
// canonically first record is retained; the disagreement is reported as
// CONFLICTING evidence rather than silently resolved.
template <class Record, class Key, class Less>
void SortAndDeduplicate(std::vector<Record>* records, Less less, Key (*key_of)(const Record&),
                        ResourceKey (*resource_of)(const Record&), std::vector<ResourceKey>* conflicted) {
  std::sort(records->begin(), records->end(), less);
  std::vector<Record> unique;
  unique.reserve(records->size());
  for (const Record& record : *records) {
    if (!unique.empty() && key_of(unique.back()) == key_of(record)) {
      if (!(unique.back() == record)) {
        conflicted->push_back(resource_of(record));
      }
      continue;
    }
    unique.push_back(record);
  }
  *records = std::move(unique);
}

Status ValidateMaskWithinModel(const Evidence<SlotMask>& mask, const SpectrumModel& model, const char* what) {
  if (!mask.HasValue()) return OkStatus();
  const SlotMask& value = mask.value();
  for (std::uint16_t slot = model.slot_count; slot < kMaxSpectrumSlots; ++slot) {
    if (value.Test(slot)) {
      return Failure(StatusCode::MalformedInput,
                     std::string(what) + " marks slot " + std::to_string(static_cast<unsigned>(slot)) +
                         " which is outside the declared spectrum model");
    }
  }
  return OkStatus();
}

}  // namespace

const char* NodeKindName(NodeKind kind) noexcept {
  switch (kind) {
    case NodeKind::Terminal:
      return "terminal";
    case NodeKind::ReconfigurableOadm:
      return "roadm";
    case NodeKind::OpticalCrossConnect:
      return "oxc";
    case NodeKind::Amplifier:
      return "amplifier";
    case NodeKind::Regenerator:
      return "regenerator";
  }
  return "terminal";
}

bool ParseNodeKind(std::string_view text, NodeKind* out) noexcept {
  if (out == nullptr) return false;
  static const struct {
    const char* name;
    NodeKind kind;
  } kTable[] = {{"terminal", NodeKind::Terminal},
                {"roadm", NodeKind::ReconfigurableOadm},
                {"oxc", NodeKind::OpticalCrossConnect},
                {"amplifier", NodeKind::Amplifier},
                {"regenerator", NodeKind::Regenerator}};
  for (const auto& entry : kTable) {
    if (text == entry.name) {
      *out = entry.kind;
      return true;
    }
  }
  return false;
}

const char* PortRoleName(PortRole role) noexcept {
  switch (role) {
    case PortRole::Client:
      return "client";
    case PortRole::Line:
      return "line";
    case PortRole::Add:
      return "add";
    case PortRole::Drop:
      return "drop";
    case PortRole::Express:
      return "express";
    case PortRole::Monitor:
      return "monitor";
  }
  return "line";
}

bool ParsePortRole(std::string_view text, PortRole* out) noexcept {
  if (out == nullptr) return false;
  static const struct {
    const char* name;
    PortRole role;
  } kTable[] = {{"client", PortRole::Client}, {"line", PortRole::Line},       {"add", PortRole::Add},
                {"drop", PortRole::Drop},     {"express", PortRole::Express}, {"monitor", PortRole::Monitor}};
  for (const auto& entry : kTable) {
    if (text == entry.name) {
      *out = entry.role;
      return true;
    }
  }
  return false;
}

const char* CrossConnectOpName(CrossConnectOp op) noexcept {
  switch (op) {
    case CrossConnectOp::Express:
      return "express";
    case CrossConnectOp::Convert:
      return "convert";
    case CrossConnectOp::Regenerate:
      return "regenerate";
  }
  return "express";
}

bool ParseCrossConnectOp(std::string_view text, CrossConnectOp* out) noexcept {
  if (out == nullptr) return false;
  if (text == "express") {
    *out = CrossConnectOp::Express;
    return true;
  }
  if (text == "convert") {
    *out = CrossConnectOp::Convert;
    return true;
  }
  if (text == "regenerate") {
    *out = CrossConnectOp::Regenerate;
    return true;
  }
  return false;
}

Status SnapshotBuilder::AddSource(SourceRecord record) {
  if (built_) {
    return Failure(StatusCode::Refused, "snapshot builder has already been sealed");
  }
  if (record.id.empty()) {
    return Failure(StatusCode::InvalidArgument, "source id must not be empty");
  }
  if (sources_.size() >= kMaxSources) {
    return Failure(StatusCode::LimitExceeded, "snapshot declares more sources than the supported maximum");
  }
  sources_.push_back(std::move(record));
  return OkStatus();
}

Status SnapshotBuilder::AddNode(NodeRecord record) {
  if (built_) {
    return Failure(StatusCode::Refused, "snapshot builder has already been sealed");
  }
  if (record.id.empty()) {
    return Failure(StatusCode::InvalidArgument, "node id must not be empty");
  }
  if (nodes_.size() >= kMaxNodes) {
    return Failure(StatusCode::LimitExceeded, "snapshot declares more nodes than the supported maximum");
  }
  nodes_.push_back(std::move(record));
  return OkStatus();
}

Status SnapshotBuilder::AddPort(PortRecord record) {
  if (built_) {
    return Failure(StatusCode::Refused, "snapshot builder has already been sealed");
  }
  if (record.key.node.empty() || record.key.port.empty()) {
    return Failure(StatusCode::InvalidArgument, "port key must name both a node and a port");
  }
  if (ports_.size() >= kMaxPorts) {
    return Failure(StatusCode::LimitExceeded, "snapshot declares more ports than the supported maximum");
  }
  ports_.push_back(std::move(record));
  return OkStatus();
}

Status SnapshotBuilder::AddSpan(SpanRecord record) {
  if (built_) {
    return Failure(StatusCode::Refused, "snapshot builder has already been sealed");
  }
  if (record.id.empty()) {
    return Failure(StatusCode::InvalidArgument, "span id must not be empty");
  }
  if (spans_.size() >= kMaxSpans) {
    return Failure(StatusCode::LimitExceeded, "snapshot declares more spans than the supported maximum");
  }
  spans_.push_back(std::move(record));
  return OkStatus();
}

Status SnapshotBuilder::AddCrossConnect(CrossConnectRecord record) {
  if (built_) {
    return Failure(StatusCode::Refused, "snapshot builder has already been sealed");
  }
  if (record.id.empty()) {
    return Failure(StatusCode::InvalidArgument, "cross-connect id must not be empty");
  }
  if (cross_connects_.size() >= kMaxCrossConnects) {
    return Failure(StatusCode::LimitExceeded, "snapshot declares more cross-connects than the supported maximum");
  }
  cross_connects_.push_back(std::move(record));
  return OkStatus();
}

Status SnapshotBuilder::AddReachProfile(ReachProfile record) {
  if (built_) {
    return Failure(StatusCode::Refused, "snapshot builder has already been sealed");
  }
  if (record.id.empty()) {
    return Failure(StatusCode::InvalidArgument, "reach profile id must not be empty");
  }
  if (profiles_.size() >= kMaxReachProfiles) {
    return Failure(StatusCode::LimitExceeded, "snapshot declares more reach profiles than the supported maximum");
  }
  profiles_.push_back(std::move(record));
  return OkStatus();
}

Expected<TopologySnapshot> SnapshotBuilder::Build() {
  if (built_) {
    return Failure(StatusCode::Refused, "snapshot builder has already been sealed");
  }
  built_ = true;

  Status status = spectrum_.Validate();
  if (status.failed()) return status;

  // --- sources -------------------------------------------------------------
  std::sort(sources_.begin(), sources_.end(), [](const SourceRecord& lhs, const SourceRecord& rhs) {
    return lhs.id < rhs.id;
  });
  for (std::size_t i = 1; i < sources_.size(); ++i) {
    if (sources_[i].id == sources_[i - 1].id) {
      return Failure(StatusCode::ConflictingEvidence,
                     "source '" + sources_[i].id.str() + "' is declared more than once in one snapshot");
    }
  }

  // --- records: sort, deduplicate, record conflicts -------------------------
  std::vector<ResourceKey> conflicted;
  conflicted.reserve(16);

  status = NormaliseDomains(nodes_, "node");
  if (status.failed()) return status;
  status = NormaliseDomains(ports_, "port");
  if (status.failed()) return status;
  status = NormaliseDomains(spans_, "span");
  if (status.failed()) return status;
  status = NormaliseDomains(cross_connects_, "cross-connect");
  if (status.failed()) return status;

  for (const NodeRecord& node : nodes_) {
    if (node.transit_cost > 0 && node.id.empty()) {
      return Failure(StatusCode::Internal, "cost accounting invariant violated for an unnamed node");
    }
  }

  for (const SpanRecord& span : spans_) {
    status = ValidateFiniteNonNegative(span.loss_db, "span.loss_db", 1.0e6);
    if (status.failed()) return status;
    status = ValidateFiniteNonNegative(span.osnr_db, "span.osnr_db", 1.0e6);
    if (status.failed()) return status;
    status = ValidateMaskWithinModel(span.blocked_slots, spectrum_, "span.blocked_slots");
    if (status.failed()) return status;
  }
  for (const PortRecord& port : ports_) {
    status = ValidateMaskWithinModel(port.blocked_slots, spectrum_, "port.blocked_slots");
    if (status.failed()) return status;
  }
  for (const CrossConnectRecord& cross_connect : cross_connects_) {
    status = ValidateMaskWithinModel(cross_connect.blocked_slots, spectrum_, "crossconnect.blocked_slots");
    if (status.failed()) return status;
  }
  for (const ReachProfile& profile : profiles_) {
    status = ValidateFiniteNonNegative(profile.max_loss_db, "profile.max_loss_db", 1.0e6);
    if (status.failed()) return status;
    status = ValidateFiniteNonNegative(profile.min_osnr_db, "profile.min_osnr_db", 1.0e6);
    if (status.failed()) return status;
    if (profile.max_span_count.HasValue() && profile.max_span_count.value() == 0) {
      return Failure(StatusCode::MalformedInput, "profile.max_span_count must be at least 1 when published");
    }
  }

  SortAndDeduplicate<NodeRecord, NodeId>(
      &nodes_, [](const NodeRecord& lhs, const NodeRecord& rhs) { return lhs.id < rhs.id; },
      [](const NodeRecord& record) { return record.id; },
      [](const NodeRecord& record) { return ResourceKey::ForNode(record.id); }, &conflicted);
  SortAndDeduplicate<PortRecord, PortKey>(
      &ports_, [](const PortRecord& lhs, const PortRecord& rhs) { return lhs.key < rhs.key; },
      [](const PortRecord& record) { return record.key; },
      [](const PortRecord& record) { return ResourceKey::ForPort(record.key); }, &conflicted);
  SortAndDeduplicate<SpanRecord, SpanId>(
      &spans_,
      [](const SpanRecord& lhs, const SpanRecord& rhs) {
        if (lhs.from != rhs.from) return lhs.from < rhs.from;
        if (lhs.to != rhs.to) return lhs.to < rhs.to;
        return lhs.id < rhs.id;
      },
      [](const SpanRecord& record) { return record.id; },
      [](const SpanRecord& record) { return ResourceKey::ForSpan(record.id); }, &conflicted);
  SortAndDeduplicate<CrossConnectRecord, CrossConnectId>(
      &cross_connects_,
      [](const CrossConnectRecord& lhs, const CrossConnectRecord& rhs) {
        if (lhs.from != rhs.from) return lhs.from < rhs.from;
        if (lhs.to != rhs.to) return lhs.to < rhs.to;
        return lhs.id < rhs.id;
      },
      [](const CrossConnectRecord& record) { return record.id; },
      [](const CrossConnectRecord& record) { return ResourceKey::ForCrossConnect(record.id); }, &conflicted);
  SortAndDeduplicate<ReachProfile, ProfileId>(
      &profiles_, [](const ReachProfile& lhs, const ReachProfile& rhs) { return lhs.id < rhs.id; },
      [](const ReachProfile& record) { return record.id; },
      [](const ReachProfile& record) { return ResourceKey::ForReachProfile(record.id); }, &conflicted);

  std::sort(conflicted.begin(), conflicted.end());
  conflicted.erase(std::unique(conflicted.begin(), conflicted.end()), conflicted.end());

  // --- adjacency -----------------------------------------------------------
  TopologySnapshot snapshot;
  snapshot.id_ = id_;
  snapshot.generation_ = generation_;
  snapshot.spectrum_ = spectrum_;
  snapshot.sources_ = std::move(sources_);
  snapshot.nodes_ = std::move(nodes_);
  snapshot.ports_ = std::move(ports_);
  snapshot.spans_ = std::move(spans_);
  snapshot.cross_connects_ = std::move(cross_connects_);
  snapshot.profiles_ = std::move(profiles_);
  snapshot.conflicted_ = std::move(conflicted);

  std::vector<ResourceKey> unresolved;
  snapshot.span_arcs_.assign(snapshot.ports_.size(), {});
  snapshot.out_cross_connects_.assign(snapshot.ports_.size(), {});
  snapshot.unresolved_at_port_.assign(snapshot.ports_.size(), 0);

  const auto port_index_of = [&snapshot](const PortKey& key) -> std::optional<std::uint32_t> {
    const auto it = std::lower_bound(snapshot.ports_.begin(), snapshot.ports_.end(), key,
                                     [](const PortRecord& record, const PortKey& value) {
                                       return record.key < value;
                                     });
    if (it == snapshot.ports_.end() || !(it->key == key)) return std::nullopt;
    return static_cast<std::uint32_t>(it - snapshot.ports_.begin());
  };

  const auto note_unresolved = [&snapshot, &unresolved](const PortKey& key, std::optional<std::uint32_t> at) {
    unresolved.push_back(ResourceKey::ForPort(key));
    if (at.has_value()) {
      snapshot.unresolved_at_port_[at.value()] += 1;
    }
  };

  // Ports whose node has no record are unresolved.
  for (std::size_t i = 0; i < snapshot.ports_.size(); ++i) {
    const auto node_it = std::lower_bound(snapshot.nodes_.begin(), snapshot.nodes_.end(),
                                          snapshot.ports_[i].key.node,
                                          [](const NodeRecord& record, const NodeId& value) {
                                            return record.id < value;
                                          });
    if (node_it == snapshot.nodes_.end() || !(node_it->id == snapshot.ports_[i].key.node)) {
      unresolved.push_back(ResourceKey::ForNode(snapshot.ports_[i].key.node));
      snapshot.unresolved_at_port_[i] += 1;
    }
  }

  for (std::size_t i = 0; i < snapshot.spans_.size(); ++i) {
    const SpanRecord& span = snapshot.spans_[i];
    if (options_.reject_self_loops && span.from == span.to) {
      return Failure(StatusCode::MalformedInput, "span '" + span.id.str() + "' starts and ends on the same port");
    }
    const auto from_index = port_index_of(span.from);
    const auto to_index = port_index_of(span.to);
    if (!from_index.has_value()) note_unresolved(span.from, to_index);
    if (!to_index.has_value()) note_unresolved(span.to, from_index);
    if (!from_index.has_value() || !to_index.has_value()) continue;
    const auto arc = SpanArc{static_cast<std::uint32_t>(i), false};
    snapshot.span_arcs_[from_index.value()].push_back(arc);
    if (span.bidirectional) {
      const auto reverse = SpanArc{static_cast<std::uint32_t>(i), true};
      snapshot.span_arcs_[to_index.value()].push_back(reverse);
    }
  }

  for (std::size_t i = 0; i < snapshot.cross_connects_.size(); ++i) {
    const CrossConnectRecord& cross_connect = snapshot.cross_connects_[i];
    if (options_.reject_self_loops && cross_connect.from == cross_connect.to) {
      return Failure(StatusCode::MalformedInput,
                     "cross-connect '" + cross_connect.id.str() + "' starts and ends on the same port");
    }
    const auto from_index = port_index_of(cross_connect.from);
    const auto to_index = port_index_of(cross_connect.to);
    if (!from_index.has_value()) note_unresolved(cross_connect.from, to_index);
    if (!to_index.has_value()) note_unresolved(cross_connect.to, from_index);
    if (!from_index.has_value() || !to_index.has_value()) continue;
    snapshot.out_cross_connects_[from_index.value()].push_back(static_cast<std::uint32_t>(i));
  }

  if (!options_.allow_unresolved_references && !unresolved.empty()) {
    return Failure(StatusCode::NotFound,
                   "snapshot references a resource with no record: " + ResourceKeyToString(unresolved.front()));
  }

  for (std::size_t i = 0; i < snapshot.span_arcs_.size(); ++i) {
    std::vector<SpanArc>& arcs = snapshot.span_arcs_[i];
    std::sort(arcs.begin(), arcs.end(), [&snapshot](const SpanArc& lhs, const SpanArc& rhs) {
      if (lhs.span_index != rhs.span_index) {
        return snapshot.spans_[lhs.span_index].id < snapshot.spans_[rhs.span_index].id;
      }
      return static_cast<int>(lhs.reversed) < static_cast<int>(rhs.reversed);
    });
  }
  for (std::vector<std::uint32_t>& list : snapshot.out_cross_connects_) {
    std::sort(list.begin(), list.end(), [&snapshot](std::uint32_t lhs, std::uint32_t rhs) {
      return snapshot.cross_connects_[lhs].id < snapshot.cross_connects_[rhs].id;
    });
  }

  std::sort(unresolved.begin(), unresolved.end());
  unresolved.erase(std::unique(unresolved.begin(), unresolved.end()), unresolved.end());
  snapshot.unresolved_ = std::move(unresolved);

  snapshot.coverage_complete_ = snapshot.unresolved_.empty() && snapshot.conflicted_.empty();
  for (const SourceRecord& source : snapshot.sources_) {
    if (source.coverage != Coverage::Complete) snapshot.coverage_complete_ = false;
  }
  // A node that publishes only part of its adjacency is a knowledge frontier
  // regardless of what its source claims.
  for (const NodeRecord& node : snapshot.nodes_) {
    if (node.coverage != Coverage::Complete) snapshot.coverage_complete_ = false;
  }

  snapshot.digest_ = ComputeSnapshotDigest(snapshot);

  nodes_.clear();
  ports_.clear();
  spans_.clear();
  cross_connects_.clear();
  profiles_.clear();
  sources_.clear();

  return snapshot;
}

const NodeRecord* TopologySnapshot::FindNode(const NodeId& id) const {
  const auto it = std::lower_bound(nodes_.begin(), nodes_.end(), id,
                                   [](const NodeRecord& record, const NodeId& value) { return record.id < value; });
  if (it == nodes_.end() || !(it->id == id)) return nullptr;
  return &(*it);
}

std::optional<std::uint32_t> TopologySnapshot::NodeIndex(const NodeId& id) const {
  const auto it = std::lower_bound(nodes_.begin(), nodes_.end(), id,
                                   [](const NodeRecord& record, const NodeId& value) { return record.id < value; });
  if (it == nodes_.end() || !(it->id == id)) return std::nullopt;
  return static_cast<std::uint32_t>(it - nodes_.begin());
}

const PortRecord* TopologySnapshot::FindPort(const PortKey& key) const {
  const auto index = PortIndex(key);
  if (!index.has_value()) return nullptr;
  return &ports_[index.value()];
}

std::optional<std::uint32_t> TopologySnapshot::PortIndex(const PortKey& key) const {
  const auto it = std::lower_bound(ports_.begin(), ports_.end(), key,
                                   [](const PortRecord& record, const PortKey& value) {
                                     return record.key < value;
                                   });
  if (it == ports_.end() || !(it->key == key)) return std::nullopt;
  return static_cast<std::uint32_t>(it - ports_.begin());
}

const ReachProfile* TopologySnapshot::FindReachProfile(const ProfileId& id) const {
  const auto it = std::lower_bound(profiles_.begin(), profiles_.end(), id,
                                   [](const ReachProfile& record, const ProfileId& value) {
                                     return record.id < value;
                                   });
  if (it == profiles_.end() || !(it->id == id)) return nullptr;
  return &(*it);
}

const std::vector<SpanArc>& TopologySnapshot::OutgoingSpanArcs(std::uint32_t port_index) const {
  if (port_index >= span_arcs_.size()) return EmptyArcs();
  return span_arcs_[port_index];
}

const std::vector<std::uint32_t>& TopologySnapshot::OutgoingCrossConnects(std::uint32_t port_index) const {
  if (port_index >= out_cross_connects_.size()) return EmptyCrossConnects();
  return out_cross_connects_[port_index];
}

Generation TopologySnapshot::SourceGeneration(const SourceId& id) const {
  const auto it = std::lower_bound(sources_.begin(), sources_.end(), id,
                                   [](const SourceRecord& record, const SourceId& value) {
                                     return record.id < value;
                                   });
  if (it == sources_.end() || !(it->id == id)) return 0;
  return it->generation;
}

bool TopologySnapshot::HasSource(const SourceId& id) const {
  const auto it = std::lower_bound(sources_.begin(), sources_.end(), id,
                                   [](const SourceRecord& record, const SourceId& value) {
                                     return record.id < value;
                                   });
  return it != sources_.end() && it->id == id;
}

bool TopologySnapshot::IsConflicted(const ResourceKey& key) const {
  return std::binary_search(conflicted_.begin(), conflicted_.end(), key);
}

const char* EvidenceFreshnessName(EvidenceFreshness freshness) noexcept {
  switch (freshness) {
    case EvidenceFreshness::Fresh:
      return "fresh";
    case EvidenceFreshness::Restored:
      return "restored";
  }
  return "restored";
}

void TopologySnapshot::MarkRestored(const IncarnationId& producer, Epoch epoch) {
  freshness_ = EvidenceFreshness::Restored;
  restored_from_incarnation_ = producer;
  restored_from_epoch_ = epoch;
}

std::uint64_t TopologySnapshot::ArcCount() const noexcept {
  std::uint64_t total = 0;
  for (const std::vector<SpanArc>& arcs : span_arcs_) total += arcs.size();
  for (const std::vector<std::uint32_t>& list : out_cross_connects_) total += list.size();
  return total;
}

}  // namespace opp
