#include "search.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <map>
#include <optional>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "opp/canonical.hpp"
#include "opp/snapshot_io.hpp"
#include "opp/version.hpp"

namespace opp {
namespace detail {
namespace {

constexpr std::uint32_t kNoIndex = 0xFFFFFFFFu;
constexpr std::size_t kCutReasonCount = static_cast<std::size_t>(CutReason::TransmitProfileUnknown) + 1;

inline std::size_t CutSlot(CutReason reason) { return static_cast<std::size_t>(reason); }

// Evidence classification for a single fact.
enum class Fact : std::uint8_t {
  Good = 0,     // published and usable
  Blocked = 1,  // published and unusable; a proven cut
  Missing = 2,  // not published; makes every conclusion through it unprovable
};

Fact ClassifyAdmin(const Evidence<AdminState>& admin) {
  if (!admin.HasValue()) return Fact::Missing;
  return admin.value() == AdminState::Up ? Fact::Good : Fact::Blocked;
}

struct PortInfo {
  SlotMask base_mask{};
  bool mask_known = false;
  Fact admin = Fact::Missing;
  bool conflicting = false;
  bool partial_coverage = false;
  bool unresolved_arcs = false;
  Fact transmit = Fact::Missing;   // Good when a reach profile id is published
  bool transmit_absent = false;    // explicitly published as "no transmitter"
  std::uint32_t profile_index = kNoIndex;
  std::uint32_t node_index = kNoIndex;
};

struct SpanInfo {
  std::uint64_t length_m = 0;
  bool length_known = false;
  double loss_db = 0.0;
  bool loss_known = false;
  double osnr_db = 0.0;
  bool osnr_known = false;
  SlotMask base_mask{};
  bool mask_known = false;
  Fact admin = Fact::Missing;
  bool conflicting = false;
  std::uint64_t cost = 0;
  const std::vector<FailureDomainId>* domains = nullptr;
};

struct CrossConnectInfo {
  SlotMask base_mask{};
  bool mask_known = false;
  Fact admin = Fact::Missing;
  bool conflicting = false;
  std::uint64_t cost = 0;
  CrossConnectOp op = CrossConnectOp::Express;
  std::uint32_t to_port = kNoIndex;
  const std::vector<FailureDomainId>* domains = nullptr;
};

struct ProfileInfo {
  bool present = false;
  bool distance_known = false;
  std::uint64_t max_distance_m = 0;
  bool spans_known = false;
  std::uint32_t max_span_count = 0;
  bool loss_known = false;
  double max_loss_db = 0.0;
  bool osnr_known = false;
  double min_osnr_db = 0.0;
};

double OsnrToInverse(double osnr_db) { return std::pow(10.0, -osnr_db / 10.0); }

double InverseToOsnr(double inverse) {
  if (inverse <= 0.0) return 1.0e9;
  return -10.0 * std::log10(inverse);
}

// Counts the resources of a candidate route that belong to one failure domain.
// The counted set is exactly what a plan reports in its exposure list: the
// source port and node, every traversed arc, the port each arc arrives at and
// the node it enters when that differs from the node it left.
struct DomainCounter {
  const std::vector<struct Label>* labels = nullptr;
  const std::vector<PortInfo>* port_info = nullptr;
  const std::vector<SpanInfo>* span_info = nullptr;
  const std::vector<CrossConnectInfo>* cross_connect_info = nullptr;
  const std::vector<NodeRecord>* nodes = nullptr;
  const std::vector<PortRecord>* ports = nullptr;

  [[nodiscard]] std::uint32_t Count(std::uint32_t parent, ArcKind kind, std::uint32_t arc_index,
                                    std::uint32_t target_port, const FailureDomainId& domain) const;
};

struct Label {
  std::uint32_t port_index = kNoIndex;
  std::uint32_t parent = kNoIndex;
  ArcKind arc_kind = ArcKind::Span;
  std::uint32_t arc_index = 0;
  bool arc_reversed = false;
  bool is_start = true;
  std::uint32_t profile_index = kNoIndex;
  SlotMask mask{};
  std::uint64_t cost = 0;
  std::uint64_t distance_m = 0;
  double loss_db = 0.0;
  double osnr_inverse = 0.0;
  std::uint32_t span_count = 0;
  std::uint32_t hops = 0;
  std::uint32_t regenerations = 0;
  std::uint32_t reason_bits = 0;
  bool proven = false;
  std::uint64_t sequence = 0;
  bool retained = false;
  bool expanded = false;
};

// A route may not stand on the same port twice. Removing a cycle from a walk can
// only lower its cost and its resource vector and can only widen its usable
// channel set, so the optimum over all walks is itself port-simple: enforcing
// this removes an unbounded family of useless labels without losing a single
// optimum.
bool PortOnPath(const std::vector<struct Label>& labels, std::uint32_t label_index, std::uint32_t port_index);

struct QueueEntry {
  std::uint64_t cost = 0;
  std::uint32_t hops = 0;
  std::uint32_t regenerations = 0;
  std::uint64_t sequence = 0;
  std::uint32_t label = 0;
};

struct QueueOrder {
  bool operator()(const QueueEntry& lhs, const QueueEntry& rhs) const {
    if (lhs.cost != rhs.cost) return lhs.cost > rhs.cost;
    if (lhs.hops != rhs.hops) return lhs.hops > rhs.hops;
    if (lhs.regenerations != rhs.regenerations) return lhs.regenerations > rhs.regenerations;
    return lhs.sequence > rhs.sequence;
  }
};

inline bool KeyLess(std::uint64_t lhs_cost, std::uint32_t lhs_hops, std::uint32_t lhs_regen, std::uint64_t rhs_cost,
                    std::uint32_t rhs_hops, std::uint32_t rhs_regen) {
  if (lhs_cost != rhs_cost) return lhs_cost < rhs_cost;
  if (lhs_hops != rhs_hops) return lhs_hops < rhs_hops;
  return lhs_regen < rhs_regen;
}

// True when "candidate" is at least as good as "reference" in every dimension
// that matters for the future, so the reference can be discarded.
bool Dominates(const Label& candidate, const Label& reference) {
  if (candidate.proven && !reference.proven) {
    // A proven label always dominates an unprovable one with the same resources.
  } else if (!candidate.proven && reference.proven) {
    return false;
  }
  if (candidate.cost > reference.cost) return false;
  if (candidate.distance_m > reference.distance_m) return false;
  if (candidate.loss_db > reference.loss_db) return false;
  if (candidate.osnr_inverse > reference.osnr_inverse) return false;
  if (candidate.span_count > reference.span_count) return false;
  if (candidate.hops > reference.hops) return false;
  if (candidate.regenerations > reference.regenerations) return false;
  if (!reference.mask.IsSubsetOf(candidate.mask)) return false;
  return true;
}

template <class T>
bool ContainsSorted(const std::vector<T>& values, const T& value) {
  return std::binary_search(values.begin(), values.end(), value);
}

bool PortOnPath(const std::vector<Label>& labels, std::uint32_t label_index, std::uint32_t port_index) {
  for (std::uint32_t cursor = label_index; cursor != kNoIndex; cursor = labels[cursor].parent) {
    if (labels[cursor].port_index == port_index) return true;
  }
  return false;
}

std::uint32_t DomainCounter::Count(std::uint32_t parent, ArcKind kind, std::uint32_t arc_index,
                                   std::uint32_t target_port, const FailureDomainId& domain) const {
  std::uint32_t count = 0;
  for (std::uint32_t cursor = parent; cursor != kNoIndex;) {
    const Label& label = (*labels)[cursor];
    if (label.is_start) {
      if (ContainsSorted((*ports)[label.port_index].failure_domains, domain)) count += 1;
      const std::uint32_t node = (*port_info)[label.port_index].node_index;
      if (node != kNoIndex && ContainsSorted((*nodes)[node].failure_domains, domain)) count += 1;
      break;
    }
    const std::vector<FailureDomainId>* arc_domains = label.arc_kind == ArcKind::Span
                                                          ? (*span_info)[label.arc_index].domains
                                                          : (*cross_connect_info)[label.arc_index].domains;
    if (arc_domains != nullptr && ContainsSorted(*arc_domains, domain)) count += 1;
    if (ContainsSorted((*ports)[label.port_index].failure_domains, domain)) count += 1;
    const std::uint32_t node = (*port_info)[label.port_index].node_index;
    const std::uint32_t parent_node = (*port_info)[(*labels)[label.parent].port_index].node_index;
    if (node != kNoIndex && node != parent_node && ContainsSorted((*nodes)[node].failure_domains, domain)) {
      count += 1;
    }
    cursor = label.parent;
  }
  const std::vector<FailureDomainId>* new_domains = kind == ArcKind::Span ? (*span_info)[arc_index].domains
                                                                          : (*cross_connect_info)[arc_index].domains;
  if (new_domains != nullptr && ContainsSorted(*new_domains, domain)) count += 1;
  if (ContainsSorted((*ports)[target_port].failure_domains, domain)) count += 1;
  const std::uint32_t target_node = (*port_info)[target_port].node_index;
  const std::uint32_t from_node = (*port_info)[(*labels)[parent].port_index].node_index;
  if (target_node != kNoIndex && target_node != from_node &&
      ContainsSorted((*nodes)[target_node].failure_domains, domain)) {
    count += 1;
  }
  return count;
}

bool DomainsIntersect(const std::vector<FailureDomainId>& domains, const std::vector<FailureDomainId>& excluded) {
  for (const FailureDomainId& domain : domains) {
    if (ContainsSorted(excluded, domain)) return true;
  }
  return false;
}

}  // namespace

SearchOutcome RunSearch(const TopologySnapshot& snapshot, const PlanningRequest& request,
                        const PlannerOptions& options, const CancelToken& cancel,
                        const SearchObserver& observer) {
  SearchOutcome outcome;
  outcome.status = OkStatus();

  const SpectrumModel& spectrum = snapshot.spectrum();
  const std::uint16_t width = request.channel_width_slots;
  const ConstraintSet& constraints = request.constraints;

  std::vector<std::uint64_t> cut_counts(kCutReasonCount, 0);
  const auto note_cut = [&cut_counts](CutReason reason) { cut_counts[CutSlot(reason)] += 1; };

  std::vector<Witness> witnesses;
  const auto note_witness = [&witnesses](CutReason reason, const ResourceKey& resource, const std::string& detail) {
    if (witnesses.size() >= kMaxWitnessEntries) return;
    for (const Witness& existing : witnesses) {
      if (existing.reason == reason && existing.resource == resource) return;
    }
    Witness witness;
    witness.reason = reason;
    witness.resource = resource;
    witness.detail = detail;
    witnesses.push_back(std::move(witness));
  };

  // ---- exclusion sets, sorted once ----------------------------------------
  std::vector<NodeId> excluded_nodes = constraints.excluded_nodes;
  std::vector<PortKey> excluded_ports = constraints.excluded_ports;
  std::vector<SpanId> excluded_spans = constraints.excluded_spans;
  std::vector<CrossConnectId> excluded_cross_connects = constraints.excluded_cross_connects;
  std::vector<FailureDomainId> excluded_domains = constraints.excluded_failure_domains;
  std::sort(excluded_nodes.begin(), excluded_nodes.end());
  std::sort(excluded_ports.begin(), excluded_ports.end());
  std::sort(excluded_spans.begin(), excluded_spans.end());
  std::sort(excluded_cross_connects.begin(), excluded_cross_connects.end());
  std::sort(excluded_domains.begin(), excluded_domains.end());

  // ---- per-resource facts -------------------------------------------------
  const std::vector<PortRecord>& ports = snapshot.ports();
  const std::vector<SpanRecord>& spans = snapshot.spans();
  const std::vector<CrossConnectRecord>& cross_connects = snapshot.cross_connects();
  const std::vector<NodeRecord>& nodes = snapshot.nodes();

  std::vector<PortInfo> port_info(ports.size());
  for (std::size_t i = 0; i < ports.size(); ++i) {
    const PortRecord& record = ports[i];
    PortInfo& info = port_info[i];
    info.admin = ClassifyAdmin(record.admin);
    info.conflicting = snapshot.IsConflicted(ResourceKey::ForPort(record.key));
    info.unresolved_arcs = snapshot.HasUnresolvedArcs(static_cast<std::uint32_t>(i));
    if (record.blocked_slots.HasValue()) {
      // The published set is the blocked set; the usable set is its complement
      // within the declared model.
      SlotMask usable = SlotMask::All(spectrum.slot_count);
      const SlotMask& blocked = record.blocked_slots.value();
      for (std::uint16_t slot = 0; slot < spectrum.slot_count; ++slot) {
        if (blocked.Test(slot)) usable.Reset(slot);
      }
      info.base_mask = usable.FirstSlotMask(width);
      info.mask_known = true;
    } else {
      info.base_mask = SlotMask::All(spectrum.slot_count).FirstSlotMask(width);
      info.mask_known = false;
    }

    const auto node_it = std::lower_bound(nodes.begin(), nodes.end(), record.key.node,
                                          [](const NodeRecord& node, const NodeId& value) { return node.id < value; });
    if (node_it != nodes.end() && node_it->id == record.key.node) {
      info.node_index = static_cast<std::uint32_t>(node_it - nodes.begin());
      if (node_it->coverage != Coverage::Complete) info.partial_coverage = true;
      if (snapshot.IsConflicted(ResourceKey::ForNode(node_it->id))) info.conflicting = true;
    } else {
      info.partial_coverage = true;
    }

    if (record.transmit_profile.HasValue()) {
      if (record.transmit_profile.value().has_value()) {
        const ProfileId& id = record.transmit_profile.value().value();
        const ReachProfile* profile = snapshot.FindReachProfile(id);
        if (profile != nullptr) {
          info.transmit = Fact::Good;
          info.profile_index = static_cast<std::uint32_t>(profile - snapshot.reach_profiles().data());
        } else {
          info.transmit = Fact::Missing;
        }
      } else {
        info.transmit_absent = true;
      }
    } else {
      info.transmit = Fact::Missing;
    }
  }

  std::vector<SpanInfo> span_info(spans.size());
  for (std::size_t i = 0; i < spans.size(); ++i) {
    const SpanRecord& record = spans[i];
    SpanInfo& info = span_info[i];
    info.domains = &record.failure_domains;
    info.cost = record.cost;
    info.admin = ClassifyAdmin(record.admin);
    info.conflicting = snapshot.IsConflicted(ResourceKey::ForSpan(record.id));
    if (record.length_m.HasValue()) {
      info.length_m = record.length_m.value();
      info.length_known = true;
    }
    if (record.loss_db.HasValue()) {
      info.loss_db = record.loss_db.value();
      info.loss_known = true;
    }
    if (record.osnr_db.HasValue()) {
      info.osnr_db = record.osnr_db.value();
      info.osnr_known = true;
    }
    if (record.blocked_slots.HasValue()) {
      SlotMask usable = SlotMask::All(spectrum.slot_count);
      const SlotMask& blocked = record.blocked_slots.value();
      for (std::uint16_t slot = 0; slot < spectrum.slot_count; ++slot) {
        if (blocked.Test(slot)) usable.Reset(slot);
      }
      info.base_mask = usable.FirstSlotMask(width);
      info.mask_known = true;
    } else {
      info.base_mask = SlotMask::All(spectrum.slot_count).FirstSlotMask(width);
      info.mask_known = false;
    }
  }

  std::vector<CrossConnectInfo> cross_connect_info(cross_connects.size());
  for (std::size_t i = 0; i < cross_connects.size(); ++i) {
    const CrossConnectRecord& record = cross_connects[i];
    CrossConnectInfo& info = cross_connect_info[i];
    info.domains = &record.failure_domains;
    info.cost = record.cost;
    info.op = record.op;
    info.admin = ClassifyAdmin(record.admin);
    info.conflicting = snapshot.IsConflicted(ResourceKey::ForCrossConnect(record.id));
    const auto to_index = snapshot.PortIndex(record.to);
    info.to_port = to_index.has_value() ? to_index.value() : kNoIndex;
    if (record.blocked_slots.HasValue()) {
      SlotMask usable = SlotMask::All(spectrum.slot_count);
      const SlotMask& blocked = record.blocked_slots.value();
      for (std::uint16_t slot = 0; slot < spectrum.slot_count; ++slot) {
        if (blocked.Test(slot)) usable.Reset(slot);
      }
      info.base_mask = usable.FirstSlotMask(width);
      info.mask_known = true;
    } else {
      info.base_mask = SlotMask::All(spectrum.slot_count).FirstSlotMask(width);
      info.mask_known = false;
    }
  }

  std::vector<ProfileInfo> profile_info(snapshot.reach_profiles().size());
  for (std::size_t i = 0; i < snapshot.reach_profiles().size(); ++i) {
    const ReachProfile& record = snapshot.reach_profiles()[i];
    ProfileInfo& info = profile_info[i];
    info.present = true;
    if (record.max_distance_m.HasValue()) {
      info.distance_known = true;
      info.max_distance_m = record.max_distance_m.value();
    }
    if (record.max_span_count.HasValue()) {
      info.spans_known = true;
      info.max_span_count = record.max_span_count.value();
    }
    if (record.max_loss_db.HasValue()) {
      info.loss_known = true;
      info.max_loss_db = record.max_loss_db.value();
    }
    if (record.min_osnr_db.HasValue()) {
      info.osnr_known = true;
      info.min_osnr_db = record.min_osnr_db.value();
    }
  }

  // A node transit cost is charged exactly once, when the route enters a node
  // that differs from the one it currently stands in.
  const auto transition_node_cost = [&](std::uint32_t from_port, std::uint32_t to_port) -> std::uint64_t {
    const std::uint32_t from_node = port_info[from_port].node_index;
    const std::uint32_t to_node = port_info[to_port].node_index;
    if (to_node == kNoIndex || to_node == from_node) return 0;
    return nodes[to_node].transit_cost;
  };

  const auto source_index = snapshot.PortIndex(request.source);
  const auto destination_index = snapshot.PortIndex(request.destination);
  if (!source_index.has_value() || !destination_index.has_value()) {
    outcome.status = Failure(StatusCode::Internal, "search requires both endpoints to exist in the snapshot");
    outcome.exhausted = true;
    return outcome;
  }

  // ---- labels -------------------------------------------------------------
  std::vector<Label> labels;
  labels.reserve(1024);
  std::priority_queue<QueueEntry, std::vector<QueueEntry>, QueueOrder> frontier;
  std::map<std::pair<std::uint32_t, std::uint32_t>, std::vector<std::uint32_t>> buckets;

  const DomainCounter domain_counter{&labels, &port_info, &span_info, &cross_connect_info, &nodes, &ports};

  std::uint64_t sequence = 0;
  const std::uint64_t label_limit = std::min(options.label_ceiling, request.max_search_labels);
  const std::uint64_t expansion_limit = std::min(options.expansion_ceiling, request.max_search_expansions);

  std::uint32_t limitations = kLimitationNone;
  const auto note_limitation = [&limitations](std::uint32_t bit) { limitations |= bit; };

  const auto push_label = [&](Label label) -> std::uint32_t {
    label.sequence = sequence++;
    labels.push_back(std::move(label));
    const std::uint32_t index = static_cast<std::uint32_t>(labels.size() - 1);
    QueueEntry entry;
    entry.cost = labels[index].cost;
    entry.hops = labels[index].hops;
    entry.regenerations = labels[index].regenerations;
    entry.sequence = labels[index].sequence;
    entry.label = index;
    frontier.push(entry);
    return index;
  };

  // ---- start label --------------------------------------------------------
  const std::uint32_t start_port = source_index.value();
  {
    Label start;
    start.port_index = start_port;
    start.is_start = true;
    start.hops = 0;
    start.reason_bits = kReasonSegmentStart;
    start.proven = true;
    const PortInfo& info = port_info[start_port];
    const PortRecord& record = ports[start_port];

    if (!ContainsSorted(excluded_ports, record.key) && !ContainsSorted(excluded_nodes, record.key.node) &&
        !DomainsIntersect(record.failure_domains, excluded_domains)) {
      start.reason_bits |= kReasonNotExcluded;
    } else {
      note_cut(CutReason::PortExcluded);
      outcome.exhausted = true;
      outcome.statistics.truncated = false;
      return outcome;
    }

    if (info.admin == Fact::Blocked) {
      note_cut(CutReason::SourceAdminDown);
      outcome.exhausted = true;
      return outcome;
    }
    if (info.admin == Fact::Missing) {
      start.proven = false;
      note_limitation(kLimitationUnknownQualityField);
      note_witness(CutReason::SourceAdminDown, ResourceKey::ForPort(record.key), "administrative state not published");
    } else {
      start.reason_bits |= kReasonAdminUp | kReasonPortAdmitted;
    }

    if (info.conflicting) {
      start.proven = false;
      note_limitation(kLimitationConflictingEvidence);
      note_witness(CutReason::ConflictingEvidence, ResourceKey::ForPort(record.key),
                   "two records disagree about this port");
    }
    if (info.partial_coverage) {
      start.proven = false;
      note_limitation(kLimitationUnknownAdjacency);
      note_witness(CutReason::PartialCoverage, ResourceKey::ForPort(record.key),
                   "the owning node does not publish complete adjacency");
    }
    if (info.unresolved_arcs) {
      start.proven = false;
      note_limitation(kLimitationUnresolvedReference);
      note_witness(CutReason::UnresolvedReference, ResourceKey::ForPort(record.key),
                   "an arc referencing this port has no record");
    }
    if (!info.mask_known) {
      start.proven = false;
      note_limitation(kLimitationUnknownSpectrum);
      note_witness(CutReason::UnknownSpectrum, ResourceKey::ForPort(record.key),
                   "port spectrum capability not published");
    }
    if (info.transmit_absent) {
      note_cut(CutReason::SegmentProfileAbsent);
      outcome.exhausted = true;
      return outcome;
    }
    if (info.transmit != Fact::Good) {
      start.proven = false;
      note_limitation(kLimitationUnknownQualityField);
      note_witness(CutReason::TransmitProfileUnknown, ResourceKey::ForPort(record.key),
                   "transmit reach profile not published");
    } else {
      start.reason_bits |= kReasonTransmitProfileKnown;
    }

    start.profile_index = info.profile_index;
    start.mask = info.base_mask;
    if (start.mask.IsEmpty()) {
      note_cut(CutReason::PortSpectrumEmpty);
      outcome.exhausted = true;
      return outcome;
    }
    start.reason_bits |= kReasonSpectrumAvailable;
    start.cost = record.transit_cost;
    if (info.node_index != kNoIndex) start.cost += nodes[info.node_index].transit_cost;
    push_label(std::move(start));
  }

  const auto destination_port = destination_index.value();
  std::uint32_t retained_destination_count = 0;
  std::uint64_t last_destination_cost = 0;
  std::uint32_t last_destination_hops = 0;
  std::uint32_t last_destination_regenerations = 0;
  bool have_destination_key = false;
  bool stopped_on_key = false;
  bool truncated = false;

  std::vector<std::uint32_t> destination_labels;

  while (!frontier.empty()) {
    if (cancel.IsRequested()) {
      outcome.status = Failure(StatusCode::Cancelled, "the caller cancelled the search");
      return outcome;
    }
    if (outcome.statistics.labels_expanded >= expansion_limit) {
      truncated = true;
      note_cut(CutReason::SearchTruncated);
      break;
    }

    const QueueEntry entry = frontier.top();
    frontier.pop();
    const std::uint32_t label_index = entry.label;
    if (labels[label_index].expanded) continue;

    if (have_destination_key && retained_destination_count >= request.max_candidates &&
        KeyLess(last_destination_cost, last_destination_hops, last_destination_regenerations, entry.cost, entry.hops,
                entry.regenerations)) {
      stopped_on_key = true;
      break;
    }

    Label current = labels[label_index];

    // Dominance check against retained labels in the same bucket. The scan runs
    // to completion even after a dominator is found: stopping early would
    // truncate the bucket and silently drop dominators, which weakens pruning
    // for every later label.
    auto& bucket = buckets[{current.port_index, current.profile_index}];
    bool dominated = false;
    std::size_t write = 0;
    for (std::size_t i = 0; i < bucket.size(); ++i) {
      const std::uint32_t other_index = bucket[i];
      if (!labels[other_index].retained) continue;
      if (Dominates(labels[other_index], current)) {
        dominated = true;
        bucket[write++] = other_index;
        continue;
      }
      if (Dominates(current, labels[other_index])) {
        labels[other_index].retained = false;
        continue;
      }
      bucket[write++] = other_index;
    }
    bucket.resize(write);
    if (dominated) {
      outcome.statistics.labels_dominated += 1;
      note_cut(CutReason::Dominated);
      continue;
    }
    bucket.push_back(label_index);
    labels[label_index].retained = true;
    labels[label_index].expanded = true;
    current = labels[label_index];

    outcome.statistics.labels_expanded += 1;
    outcome.statistics.states_visited = buckets.size();
    if (frontier.size() > outcome.statistics.peak_frontier) {
      outcome.statistics.peak_frontier = frontier.size();
    }
    if (observer) observer(outcome.statistics);

    if (current.port_index == destination_port) {
      destination_labels.push_back(label_index);
      retained_destination_count += 1;
      last_destination_cost = current.cost;
      last_destination_hops = current.hops;
      last_destination_regenerations = current.regenerations;
      have_destination_key = true;
      continue;
    }

    // ---- expand cross-connect arcs ---------------------------------------
    const PortRecord& from_port = ports[current.port_index];
    const ProfileInfo* profile =
        current.profile_index == kNoIndex ? nullptr : &profile_info[current.profile_index];

    for (std::uint32_t cross_index : snapshot.OutgoingCrossConnects(current.port_index)) {
      outcome.statistics.arcs_examined += 1;
      const CrossConnectRecord& record = cross_connects[cross_index];
      const CrossConnectInfo& info = cross_connect_info[cross_index];

      if (ContainsSorted(excluded_cross_connects, record.id) || ContainsSorted(excluded_nodes, record.to.node) ||
          ContainsSorted(excluded_ports, record.to)) {
        note_cut(CutReason::PortExcluded);
        continue;
      }
      if (info.conflicting) {
        note_limitation(kLimitationConflictingEvidence);
        note_witness(CutReason::ConflictingEvidence, ResourceKey::ForCrossConnect(record.id),
                     "two records disagree about this cross-connect");
      }
      if (info.admin == Fact::Blocked) {
        note_cut(CutReason::CrossConnectAdminDown);
        continue;
      }
      if (info.to_port == kNoIndex) {
        note_cut(CutReason::UnresolvedReference);
        continue;
      }
      if (info.domains != nullptr && DomainsIntersect(*info.domains, excluded_domains)) {
        note_cut(CutReason::FailureDomainExcluded);
        continue;
      }
      if (record.op == CrossConnectOp::Regenerate && !constraints.allow_regeneration) {
        note_cut(CutReason::RegenerationNotAllowed);
        continue;
      }
      if (record.op == CrossConnectOp::Convert && !constraints.allow_wavelength_conversion) {
        note_cut(CutReason::ConversionNotAllowed);
        continue;
      }
      if (record.op == CrossConnectOp::Regenerate &&
          current.regenerations >= request.max_regenerations) {
        note_cut(CutReason::RegenerationLimitExceeded);
        continue;
      }
      if (current.hops + 1 > request.max_hops) {
        note_cut(CutReason::HopLimitExceeded);
        continue;
      }
      if (PortOnPath(labels, label_index, info.to_port)) {
        note_cut(CutReason::LoopPrevented);
        continue;
      }

      std::uint64_t next_cost = 0;
      if (!AddCheckedU64(current.cost, info.cost, &next_cost) ||
          !AddCheckedU64(next_cost, ports[info.to_port].transit_cost, &next_cost) ||
          !AddCheckedU64(next_cost, transition_node_cost(current.port_index, info.to_port), &next_cost)) {
        note_cut(CutReason::CostLimitExceeded);
        continue;
      }
      if (request.max_total_cost.has_value() && next_cost > request.max_total_cost.value()) {
        note_cut(CutReason::CostLimitExceeded);
        continue;
      }

      // Domain member limits apply to the resources the route would use.
      if (!constraints.max_members_per_failure_domain.empty()) {
        bool exceeded = false;
        for (const auto& limit : constraints.max_members_per_failure_domain) {
          if (domain_counter.Count(label_index, ArcKind::CrossConnect, cross_index, info.to_port, limit.first) >
              limit.second) {
            exceeded = true;
            break;
          }
        }
        if (exceeded) {
          note_cut(CutReason::FailureDomainMemberLimit);
          continue;
        }
      }

      Label next;
      next.port_index = info.to_port;
      next.parent = label_index;
      next.arc_kind = ArcKind::CrossConnect;
      next.arc_index = cross_index;
      next.arc_reversed = false;
      next.is_start = false;
      next.hops = current.hops + 1;
      next.cost = next_cost;
      next.distance_m = current.distance_m;
      next.loss_db = current.loss_db;
      next.osnr_inverse = current.osnr_inverse;
      next.span_count = current.span_count;
      next.regenerations = current.regenerations;
      next.proven = current.proven;
      next.reason_bits = kReasonNotExcluded | kReasonPortAdmitted;

      const PortInfo& target_info = port_info[info.to_port];
      const PortRecord& target_record = ports[info.to_port];
      if (info.admin == Fact::Good) {
        next.reason_bits |= kReasonAdminUp;
      } else {
        next.proven = false;
        note_limitation(kLimitationUnknownQualityField);
        note_witness(CutReason::CrossConnectAdminDown, ResourceKey::ForCrossConnect(record.id),
                     "administrative state not published");
      }
      if (target_info.admin == Fact::Good) {
        next.reason_bits |= kReasonAdminUp;
      } else if (target_info.admin == Fact::Blocked) {
        note_cut(CutReason::DestinationAdminDown);
        continue;
      } else {
        next.proven = false;
        note_limitation(kLimitationUnknownQualityField);
        note_witness(CutReason::DestinationAdminDown, ResourceKey::ForPort(target_record.key),
                     "administrative state not published");
      }
      if (target_info.conflicting) {
        next.proven = false;
        note_limitation(kLimitationConflictingEvidence);
        note_witness(CutReason::ConflictingEvidence, ResourceKey::ForPort(target_record.key),
                     "two records disagree about this port");
      }
      if (target_info.partial_coverage) {
        next.proven = false;
        note_limitation(kLimitationUnknownAdjacency);
        note_witness(CutReason::PartialCoverage, ResourceKey::ForPort(target_record.key),
                     "the owning node does not publish complete adjacency");
      }
      if (target_info.unresolved_arcs) {
        next.proven = false;
        note_limitation(kLimitationUnresolvedReference);
        note_witness(CutReason::UnresolvedReference, ResourceKey::ForPort(target_record.key),
                     "an arc referencing this port has no record");
      }
      if (!info.mask_known || !target_info.mask_known) {
        next.proven = false;
        note_limitation(kLimitationUnknownSpectrum);
        note_witness(CutReason::UnknownSpectrum, ResourceKey::ForCrossConnect(record.id),
                     "spectrum capability not published");
      }

      switch (record.op) {
        case CrossConnectOp::Express: {
          next.mask = current.mask.Intersect(info.base_mask).Intersect(target_info.base_mask);
          next.profile_index = current.profile_index;
          break;
        }
        case CrossConnectOp::Convert: {
          next.mask = target_info.base_mask;
          next.profile_index = current.profile_index;
          next.reason_bits |= kReasonWavelengthConversion;
          break;
        }
        case CrossConnectOp::Regenerate: {
          if (target_info.transmit_absent) {
            note_cut(CutReason::SegmentProfileAbsent);
            continue;
          }
          if (target_info.transmit != Fact::Good) {
            next.proven = false;
            note_limitation(kLimitationUnknownQualityField);
            note_witness(CutReason::TransmitProfileUnknown, ResourceKey::ForPort(target_record.key),
                         "transmit reach profile not published");
          }
          next.profile_index = target_info.profile_index;
          next.mask = target_info.base_mask;
          next.distance_m = 0;
          next.loss_db = 0.0;
          next.osnr_inverse = 0.0;
          next.span_count = 0;
          next.regenerations = current.regenerations + 1;
          next.reason_bits |= kReasonRegenerationBoundary | kReasonSegmentStart | kReasonTransmitProfileKnown;
          break;
        }
      }

      if (next.mask.IsEmpty()) {
        note_cut(CutReason::PortSpectrumEmpty);
        continue;
      }
      next.reason_bits |= kReasonSpectrumAvailable;
      if (next.profile_index != kNoIndex) {
        next.reason_bits |= kReasonWithinReachDistance | kReasonWithinReachSpans | kReasonWithinReachLoss |
                            kReasonWithinReachOsnr;
      }
      next.reason_bits |= kReasonFailureDomainWithinLimit;
      if (labels.size() >= label_limit) {
        truncated = true;
        note_cut(CutReason::SearchTruncated);
        break;
      }
      push_label(std::move(next));
    }
    if (truncated) break;

    // ---- expand span arcs -------------------------------------------------
    for (const SpanArc& arc : snapshot.OutgoingSpanArcs(current.port_index)) {
      outcome.statistics.arcs_examined += 1;
      const SpanRecord& record = spans[arc.span_index];
      const SpanInfo& info = span_info[arc.span_index];

      const PortKey& to_key = arc.reversed ? record.from : record.to;
      const auto to_index_opt = snapshot.PortIndex(to_key);
      if (!to_index_opt.has_value()) {
        note_cut(CutReason::UnresolvedReference);
        continue;
      }
      const std::uint32_t to_index = to_index_opt.value();
      const PortInfo& target_info = port_info[to_index];
      const PortRecord& target_record = ports[to_index];

      if (ContainsSorted(excluded_spans, record.id) || ContainsSorted(excluded_nodes, to_key.node) ||
          ContainsSorted(excluded_ports, to_key)) {
        note_cut(CutReason::SpanExcluded);
        continue;
      }
      if (info.domains != nullptr && DomainsIntersect(*info.domains, excluded_domains)) {
        note_cut(CutReason::FailureDomainExcluded);
        continue;
      }
      if (info.admin == Fact::Blocked) {
        note_cut(CutReason::SpanAdminDown);
        continue;
      }
      if (current.hops + 1 > request.max_hops) {
        note_cut(CutReason::HopLimitExceeded);
        continue;
      }
      // Immediate backtracking over the same span, or straight back to the
      // previous port, is always removable from a route.
      if (!current.is_start && current.arc_kind == ArcKind::Span && current.arc_index == arc.span_index) {
        note_cut(CutReason::LoopPrevented);
        continue;
      }
      if (PortOnPath(labels, label_index, to_index)) {
        note_cut(CutReason::LoopPrevented);
        continue;
      }

      std::uint64_t next_cost = 0;
      if (!AddCheckedU64(current.cost, info.cost, &next_cost) ||
          !AddCheckedU64(next_cost, target_record.transit_cost, &next_cost) ||
          !AddCheckedU64(next_cost, transition_node_cost(current.port_index, to_index), &next_cost)) {
        note_cut(CutReason::CostLimitExceeded);
        continue;
      }
      if (request.max_total_cost.has_value() && next_cost > request.max_total_cost.value()) {
        note_cut(CutReason::CostLimitExceeded);
        continue;
      }

      if (!constraints.max_members_per_failure_domain.empty()) {
        bool exceeded = false;
        for (const auto& limit : constraints.max_members_per_failure_domain) {
          if (domain_counter.Count(label_index, ArcKind::Span, arc.span_index, to_index, limit.first) >
              limit.second) {
            exceeded = true;
            break;
          }
        }
        if (exceeded) {
          note_cut(CutReason::FailureDomainMemberLimit);
          continue;
        }
      }

      Label next;
      next.port_index = to_index;
      next.parent = label_index;
      next.arc_kind = ArcKind::Span;
      next.arc_index = arc.span_index;
      next.arc_reversed = arc.reversed;
      next.is_start = false;
      next.hops = current.hops + 1;
      next.cost = next_cost;
      next.span_count = current.span_count + 1;
      next.regenerations = current.regenerations;
      next.profile_index = current.profile_index;
      next.proven = current.proven;
      next.reason_bits = kReasonNotExcluded | kReasonPortAdmitted;

      // Accumulate impairment. An unpublished quantity contributes nothing,
      // which is optimistic and is exactly why the label becomes unprovable.
      std::uint64_t next_distance = current.distance_m;
      if (info.length_known) {
        if (!AddCheckedU64(next_distance, info.length_m, &next_distance)) {
          note_cut(CutReason::TotalDistanceExceeded);
          continue;
        }
      } else {
        next.proven = false;
        note_limitation(kLimitationUnknownQualityField);
        note_witness(CutReason::UnknownQualityField, ResourceKey::ForSpan(record.id),
                     "span length not published");
      }
      double next_loss = current.loss_db;
      if (info.loss_known) {
        next_loss += info.loss_db;
      } else {
        next.proven = false;
        note_limitation(kLimitationUnknownQualityField);
        note_witness(CutReason::UnknownQualityField, ResourceKey::ForSpan(record.id), "span loss not published");
      }
      double next_osnr_inverse = current.osnr_inverse;
      if (info.osnr_known) {
        next_osnr_inverse += OsnrToInverse(info.osnr_db);
      } else {
        next.proven = false;
        note_limitation(kLimitationUnknownQualityField);
        note_witness(CutReason::UnknownQualityField, ResourceKey::ForSpan(record.id), "span OSNR not published");
      }
      next.distance_m = next_distance;
      next.loss_db = next_loss;
      next.osnr_inverse = next_osnr_inverse;

      if (info.admin != Fact::Good) {
        next.proven = false;
        note_limitation(kLimitationUnknownQualityField);
        note_witness(CutReason::SpanAdminDown, ResourceKey::ForSpan(record.id),
                     "administrative state not published");
      } else {
        next.reason_bits |= kReasonAdminUp;
      }
      if (info.conflicting) {
        next.proven = false;
        note_limitation(kLimitationConflictingEvidence);
        note_witness(CutReason::ConflictingEvidence, ResourceKey::ForSpan(record.id),
                     "two records disagree about this span");
      }
      if (target_info.admin == Fact::Good) {
        next.reason_bits |= kReasonAdminUp;
      } else if (target_info.admin == Fact::Blocked) {
        note_cut(CutReason::DestinationAdminDown);
        continue;
      } else {
        next.proven = false;
        note_limitation(kLimitationUnknownQualityField);
        note_witness(CutReason::DestinationAdminDown, ResourceKey::ForPort(target_record.key),
                     "administrative state not published");
      }
      if (target_info.conflicting) {
        next.proven = false;
        note_limitation(kLimitationConflictingEvidence);
        note_witness(CutReason::ConflictingEvidence, ResourceKey::ForPort(target_record.key),
                     "two records disagree about this port");
      }
      if (target_info.partial_coverage) {
        next.proven = false;
        note_limitation(kLimitationUnknownAdjacency);
        note_witness(CutReason::PartialCoverage, ResourceKey::ForPort(target_record.key),
                     "the owning node does not publish complete adjacency");
      }
      if (target_info.unresolved_arcs) {
        next.proven = false;
        note_limitation(kLimitationUnresolvedReference);
        note_witness(CutReason::UnresolvedReference, ResourceKey::ForPort(target_record.key),
                     "an arc referencing this port has no record");
      }
      if (!info.mask_known || !target_info.mask_known) {
        next.proven = false;
        note_limitation(kLimitationUnknownSpectrum);
        note_witness(CutReason::UnknownSpectrum, ResourceKey::ForSpan(record.id),
                     "span spectrum availability not published");
      }

      next.mask = current.mask.Intersect(info.base_mask).Intersect(target_info.base_mask);
      if (next.mask.IsEmpty()) {
        note_cut(CutReason::PortSpectrumEmpty);
        continue;
      }
      next.reason_bits |= kReasonSpectrumAvailable;

      if (profile != nullptr && profile->present) {
        if (profile->spans_known && next.span_count > profile->max_span_count) {
          note_cut(CutReason::ReachSpanCountExceeded);
          continue;
        }
        if (profile->distance_known && next.distance_m > profile->max_distance_m) {
          note_cut(CutReason::ReachDistanceExceeded);
          continue;
        }
        if (profile->loss_known && next.loss_db > profile->max_loss_db + 1.0e-9) {
          note_cut(CutReason::ReachLossExceeded);
          continue;
        }
        if (profile->osnr_known) {
          const double segment_osnr = InverseToOsnr(next.osnr_inverse);
          const double floor_db =
              constraints.min_segment_osnr_db.has_value()
                  ? std::max(profile->min_osnr_db, constraints.min_segment_osnr_db.value())
                  : profile->min_osnr_db;
          if (segment_osnr + 1.0e-9 < floor_db) {
            note_cut(CutReason::ReachOsnrBelowMinimum);
            continue;
          }
          next.reason_bits |= kReasonWithinReachOsnr;
        } else {
          next.proven = false;
          note_limitation(kLimitationUnknownQualityField);
          note_witness(CutReason::UnknownQualityField,
                       ResourceKey::ForReachProfile(snapshot.reach_profiles()[current.profile_index].id),
                       "reach profile minimum OSNR not published");
        }
        if (profile->spans_known) next.reason_bits |= kReasonWithinReachSpans;
        if (profile->distance_known) next.reason_bits |= kReasonWithinReachDistance;
        if (profile->loss_known) next.reason_bits |= kReasonWithinReachLoss;
      } else {
        next.proven = false;
        note_limitation(kLimitationUnknownQualityField);
        note_witness(CutReason::TransmitProfileUnknown,
                     ResourceKey::ForPort(from_port.key), "no reach profile applies to this segment");
      }

      if (constraints.min_segment_osnr_db.has_value() && (profile == nullptr || !profile->osnr_known)) {
        const double segment_osnr = InverseToOsnr(next.osnr_inverse);
        if (segment_osnr + 1.0e-9 < constraints.min_segment_osnr_db.value()) {
          note_cut(CutReason::ReachOsnrBelowMinimum);
          continue;
        }
      }

      if (constraints.max_total_distance_m.has_value() && next.distance_m > constraints.max_total_distance_m.value()) {
        note_cut(CutReason::TotalDistanceExceeded);
        continue;
      }
      if (constraints.max_total_span_count.has_value() &&
          next.span_count > constraints.max_total_span_count.value()) {
        note_cut(CutReason::TotalSpanCountExceeded);
        continue;
      }
      if (constraints.max_total_loss_db.has_value() && next.loss_db > constraints.max_total_loss_db.value() + 1.0e-9) {
        note_cut(CutReason::TotalLossExceeded);
        continue;
      }

      next.reason_bits |= kReasonFailureDomainWithinLimit;
      if (labels.size() >= label_limit) {
        truncated = true;
        note_cut(CutReason::SearchTruncated);
        break;
      }
      push_label(std::move(next));
    }
    if (truncated) break;
  }

  if (truncated) {
    limitations |= kLimitationSearchTruncated;
  }

  outcome.exhausted = frontier.empty() && !truncated;
  outcome.statistics.truncated = truncated;
  outcome.statistics.labels_created = labels.size();
  outcome.limitations = limitations;
  outcome.witnesses = std::move(witnesses);

  for (std::size_t i = 0; i < kCutReasonCount; ++i) {
    if (cut_counts[i] == 0) continue;
    CutCount entry;
    entry.reason = static_cast<CutReason>(i);
    entry.count = cut_counts[i];
    outcome.cuts.push_back(entry);
  }

  // Reconstruct the retained destination paths in the order they were settled.
  for (std::uint32_t index : destination_labels) {
    if (!labels[index].retained) continue;
    RawPath path;
    path.cost = labels[index].cost;
    path.hops = labels[index].hops;
    path.regenerations = labels[index].regenerations;
    path.proven = labels[index].proven;
    for (std::uint32_t cursor = index; cursor != kNoIndex;) {
      const Label& label = labels[cursor];
      if (label.is_start) break;
      ArcRef arc;
      arc.kind = label.arc_kind;
      arc.index = label.arc_index;
      arc.reversed = label.arc_reversed;
      path.arcs.push_back(arc);
      cursor = label.parent;
    }
    std::reverse(path.arcs.begin(), path.arcs.end());
    outcome.paths.push_back(std::move(path));
  }

  outcome.proved_optimum = (stopped_on_key || outcome.exhausted) && !truncated && snapshot.coverage_complete();
  // A path that is not provable never contributes to a FEASIBLE outcome, so the
  // optimum claim is limited to the proven candidates.
  if (!outcome.paths.empty()) {
    bool any_proven = false;
    for (const RawPath& path : outcome.paths) {
      if (path.proven) {
        any_proven = true;
        break;
      }
    }
    if (!any_proven) outcome.proved_optimum = false;
  }
  return outcome;
}


Expected<PortKey> ArrivalPort(const TopologySnapshot& snapshot, const ArcRef& arc) {
  if (arc.kind == ArcKind::Span) {
    if (arc.index >= snapshot.spans().size()) {
      return Failure(StatusCode::Internal, "span arc index is out of range");
    }
    const SpanRecord& record = snapshot.spans()[arc.index];
    return arc.reversed ? record.from : record.to;
  }
  if (arc.index >= snapshot.cross_connects().size()) {
    return Failure(StatusCode::Internal, "cross-connect arc index is out of range");
  }
  return snapshot.cross_connects()[arc.index].to;
}

Expected<PortKey> DeparturePort(const TopologySnapshot& snapshot, const ArcRef& arc) {
  if (arc.kind == ArcKind::Span) {
    if (arc.index >= snapshot.spans().size()) {
      return Failure(StatusCode::Internal, "span arc index is out of range");
    }
    const SpanRecord& record = snapshot.spans()[arc.index];
    return arc.reversed ? record.to : record.from;
  }
  if (arc.index >= snapshot.cross_connects().size()) {
    return Failure(StatusCode::Internal, "cross-connect arc index is out of range");
  }
  return snapshot.cross_connects()[arc.index].from;
}

std::vector<ArcRef> StripCycles(const TopologySnapshot& snapshot, const PortKey& source,
                                const std::vector<ArcRef>& arcs) {
  std::vector<ArcRef> output;
  std::vector<PortKey> visited;
  output.reserve(arcs.size());
  visited.reserve(arcs.size() + 1);
  visited.push_back(source);
  for (const ArcRef& arc : arcs) {
    const Expected<PortKey> arrival = ArrivalPort(snapshot, arc);
    if (!arrival.ok()) break;
    const auto it = std::find(visited.begin(), visited.end(), arrival.value());
    if (it != visited.end()) {
      // The walk already stands on this port, so everything from there to here is
      // a removable cycle and the arc itself is redundant.
      const std::size_t position = static_cast<std::size_t>(it - visited.begin());
      output.resize(position);
      visited.resize(position + 1);
      continue;
    }
    output.push_back(arc);
    visited.push_back(arrival.value());
  }
  return output;
}

namespace {

std::string FormatSafeDouble(double value) {
  const Expected<std::string> text = FormatDouble(value);
  return text.ok() ? text.value() : std::string("0");
}

}  // namespace

Expected<PlanArtifact> BuildPlan(const TopologySnapshot& snapshot, const PlanningRequest& request,
                                 const Digest256& request_digest, const std::vector<ArcRef>& arcs,
                                 Digest256* out_digest) {
  const SpectrumModel& spectrum = snapshot.spectrum();
  const std::uint16_t width = request.channel_width_slots;

  const auto usable_mask = [&spectrum, width](const Evidence<SlotMask>& blocked) -> SlotMask {
    SlotMask usable = SlotMask::All(spectrum.slot_count);
    if (blocked.HasValue()) {
      for (std::uint16_t slot = 0; slot < spectrum.slot_count; ++slot) {
        if (blocked.value().Test(slot)) usable.Reset(slot);
      }
    }
    return usable.FirstSlotMask(width);
  };

  PlanArtifact plan;
  plan.format_version = kPlanFormatVersion;
  plan.rule_version = kPlanningRuleVersion;
  plan.request_id = request.id;
  plan.request_digest = request_digest;
  plan.snapshot_id = snapshot.id();
  plan.snapshot_generation = snapshot.generation();
  plan.snapshot_digest = snapshot.digest();
  plan.source = request.source;
  plan.destination = request.destination;
  plan.channel_width_slots = width;

  for (const SourceRecord& source : snapshot.sources()) {
    SourceBinding binding;
    binding.source = source.id;
    binding.generation = source.generation;
    binding.snapshot_contribution = SourceContributionDigest(snapshot, source.id);
    plan.bound_sources.push_back(std::move(binding));
  }

  const PortRecord* start_port = snapshot.FindPort(request.source);
  if (start_port == nullptr) {
    return Failure(StatusCode::Internal, "plan build requires the source port to exist");
  }
  if (!start_port->transmit_profile.HasValue() || !start_port->transmit_profile.value().has_value()) {
    return Failure(StatusCode::Internal, "plan build requires a published transmit profile at the source port");
  }
  if (!start_port->blocked_slots.HasValue()) {
    return Failure(StatusCode::Internal, "plan build requires a published spectrum capability at the source port");
  }

  std::vector<PlanStep> steps;
  std::vector<PlanSegment> segments;
  std::vector<PlanReservation> reservations;
  std::vector<PlanAssumption> capability;
  std::vector<PlanAssumption> quality;
  std::vector<FailureDomainExposure> exposures;
  std::map<FailureDomainId, std::uint32_t> domain_counts;

  const auto note_domains = [&domain_counts](const std::vector<FailureDomainId>& domains) {
    for (const FailureDomainId& domain : domains) domain_counts[domain] += 1;
  };

  std::uint32_t step_index = 0;
  const auto push_step = [&steps, &step_index](StepKind kind, const ResourceKey& resource, std::uint32_t segment,
                                               std::uint32_t reasons, std::uint64_t cost) {
    PlanStep step;
    step.index = step_index++;
    step.kind = kind;
    step.resource = resource;
    step.segment_index = segment;
    step.reason_bits = reasons;
    step.cost = cost;
    steps.push_back(std::move(step));
  };

  push_step(StepKind::Port, ResourceKey::ForPort(request.source), 0,
            kReasonSegmentStart | kReasonNotExcluded | kReasonAdminUp | kReasonPortAdmitted |
                kReasonSpectrumAvailable | kReasonTransmitProfileKnown,
            0);
  {
    PlanAssumption transmit_assumption;
    transmit_assumption.resource = ResourceKey::ForPort(request.source);
    transmit_assumption.field = "transmit_profile";
    transmit_assumption.value = start_port->transmit_profile.value().value().str();
    capability.push_back(std::move(transmit_assumption));

    PlanAssumption spectrum_assumption;
    spectrum_assumption.resource = ResourceKey::ForPort(request.source);
    spectrum_assumption.field = "blocked_slots";
    spectrum_assumption.value = start_port->blocked_slots.value().ToHex();
    capability.push_back(std::move(spectrum_assumption));
  }
  note_domains(start_port->failure_domains);

  const NodeRecord* start_node = snapshot.FindNode(request.source.node);
  if (start_node != nullptr) {
    push_step(StepKind::Node, ResourceKey::ForNode(start_node->id), 0,
              kReasonSegmentStart | kReasonNotExcluded | kReasonAdminUp, start_node->transit_cost);
    note_domains(start_node->failure_domains);
  }

  const auto transition_node_cost = [&snapshot](const PortKey& from, const PortKey& to) -> std::uint64_t {
    if (from.node == to.node) return 0;
    const NodeRecord* node = snapshot.FindNode(to.node);
    return node == nullptr ? 0 : node->transit_cost;
  };

  ProfileId current_profile = start_port->transmit_profile.value().value();
  SlotMask mask = usable_mask(start_port->blocked_slots);
  std::uint64_t total_cost = start_port->transit_cost;
  if (start_node != nullptr) total_cost += start_node->transit_cost;
  std::uint64_t segment_distance = 0;
  double segment_loss = 0.0;
  double segment_osnr_inverse = 0.0;
  std::uint32_t segment_span_count = 0;
  std::uint32_t segment_channel_runs = 0;
  std::optional<std::uint16_t> segment_last_slot;
  std::uint32_t segment_index = 0;
  std::uint32_t regenerations = 0;
  PortKey current_port = request.source;

  // Segments are created lazily so their span list and totals are filled in as
  // the walk proceeds.
  const auto ensure_segment = [&segments, &segment_index, &current_profile]() {
    if (!segments.empty() && segments.back().index == segment_index) return;
    PlanSegment segment;
    segment.index = segment_index;
    segment.profile = current_profile;
    segments.push_back(std::move(segment));
  };

  for (const ArcRef& arc : arcs) {
    if (arc.kind == ArcKind::Span) {
      if (arc.index >= snapshot.spans().size()) {
        return Failure(StatusCode::Internal, "plan build saw an out-of-range span arc");
      }
      const SpanRecord& span = snapshot.spans()[arc.index];
      if (!span.length_m.HasValue() || !span.loss_db.HasValue() || !span.osnr_db.HasValue() ||
          !span.blocked_slots.HasValue() || !span.admin.HasValue()) {
        return Failure(StatusCode::Internal, "plan build requires published span quality evidence");
      }
      const PortKey arrival = arc.reversed ? span.from : span.to;
      const PortRecord* arrival_port = snapshot.FindPort(arrival);
      if (arrival_port == nullptr || !arrival_port->blocked_slots.HasValue()) {
        return Failure(StatusCode::Internal, "plan build requires the arrival port spectrum capability");
      }
      mask = mask.Intersect(usable_mask(span.blocked_slots)).Intersect(usable_mask(arrival_port->blocked_slots));
      const std::optional<std::uint16_t> slot = mask.LowestSetBit();
      if (!slot.has_value()) {
        return Failure(StatusCode::Internal, "plan build derived an empty channel set");
      }
      if (!segment_last_slot.has_value() || segment_last_slot.value() != slot.value()) {
        segment_channel_runs += 1;
        segment_last_slot = slot;
      }

      ensure_segment();
      PlanSpanUse use;
      use.id = span.id;
      use.from = arc.reversed ? span.to : span.from;
      use.to = arrival;
      use.reversed = arc.reversed;
      use.length_m = span.length_m.value();
      use.loss_db = span.loss_db.value();
      use.osnr_db = span.osnr_db.value();
      use.cost = span.cost;
      use.first_slot = slot.value();
      use.failure_domains = span.failure_domains;
      segments.back().spans.push_back(use);
      segment_distance += use.length_m;
      segment_loss += use.loss_db;
      segment_osnr_inverse += std::pow(10.0, -use.osnr_db / 10.0);
      segment_span_count += 1;
      total_cost += use.cost;

      const std::uint32_t reasons =
          kReasonNotExcluded | kReasonAdminUp | kReasonPortAdmitted | kReasonSpectrumAvailable |
          kReasonWithinReachDistance | kReasonWithinReachSpans | kReasonWithinReachLoss | kReasonWithinReachOsnr |
          kReasonFailureDomainWithinLimit;
      push_step(StepKind::Span, ResourceKey::ForSpan(span.id), segment_index, reasons, use.cost);
      note_domains(span.failure_domains);
      note_domains(arrival_port->failure_domains);
      total_cost += arrival_port->transit_cost;

      const std::uint64_t node_cost = transition_node_cost(current_port, arrival);
      total_cost += node_cost;
      if (!(arrival.node == current_port.node)) {
        const NodeRecord* node = snapshot.FindNode(arrival.node);
        if (node != nullptr) {
          push_step(StepKind::Node, ResourceKey::ForNode(node->id), segment_index,
                    kReasonNotExcluded | kReasonAdminUp, node_cost);
          note_domains(node->failure_domains);
        }
      }

      PlanReservation reservation;
      reservation.resource = ResourceKey::ForSpan(span.id);
      reservation.channel = Channel{slot.value(), width};
      reservation.segment_index = segment_index;
      reservations.push_back(std::move(reservation));

      const ResourceKey span_key = ResourceKey::ForSpan(span.id);
      PlanAssumption length_assumption;
      length_assumption.resource = span_key;
      length_assumption.field = "length_m";
      length_assumption.value = FormatU64(use.length_m);
      quality.push_back(std::move(length_assumption));

      PlanAssumption loss_assumption;
      loss_assumption.resource = span_key;
      loss_assumption.field = "loss_db";
      loss_assumption.value = FormatSafeDouble(use.loss_db);
      quality.push_back(std::move(loss_assumption));

      PlanAssumption osnr_assumption;
      osnr_assumption.resource = span_key;
      osnr_assumption.field = "osnr_db";
      osnr_assumption.value = FormatSafeDouble(use.osnr_db);
      quality.push_back(std::move(osnr_assumption));

      PlanAssumption spectrum_assumption;
      spectrum_assumption.resource = span_key;
      spectrum_assumption.field = "blocked_slots";
      spectrum_assumption.value = span.blocked_slots.value().ToHex();
      capability.push_back(std::move(spectrum_assumption));

      current_port = arrival;
      continue;
    }

    if (arc.index >= snapshot.cross_connects().size()) {
      return Failure(StatusCode::Internal, "plan build saw an out-of-range cross-connect arc");
    }
    const CrossConnectRecord& cross_connect = snapshot.cross_connects()[arc.index];
    if (!cross_connect.admin.HasValue() || !cross_connect.blocked_slots.HasValue()) {
      return Failure(StatusCode::Internal, "plan build requires published cross-connect evidence");
    }
    const PortRecord* target_port = snapshot.FindPort(cross_connect.to);
    if (target_port == nullptr || !target_port->blocked_slots.HasValue()) {
      return Failure(StatusCode::Internal, "plan build requires the target port spectrum capability");
    }

    std::uint32_t reasons = kReasonNotExcluded | kReasonAdminUp | kReasonPortAdmitted;
    if (cross_connect.op == CrossConnectOp::Express) {
      mask = mask.Intersect(usable_mask(cross_connect.blocked_slots))
                 .Intersect(usable_mask(target_port->blocked_slots));
      const std::optional<std::uint16_t> slot = mask.LowestSetBit();
      if (!slot.has_value()) {
        return Failure(StatusCode::Internal, "plan build derived an empty channel set after a cross-connect");
      }
      if (!segment_last_slot.has_value() || segment_last_slot.value() != slot.value()) {
        segment_channel_runs += 1;
        segment_last_slot = slot;
      }
    } else if (cross_connect.op == CrossConnectOp::Convert) {
      reasons |= kReasonWavelengthConversion;
      mask = usable_mask(target_port->blocked_slots);
      const std::optional<std::uint16_t> slot = mask.LowestSetBit();
      if (!slot.has_value()) {
        return Failure(StatusCode::Internal, "plan build derived an empty channel set after a conversion");
      }
      segment_channel_runs += 1;
      segment_last_slot = slot;
    } else {
      reasons |= kReasonRegenerationBoundary | kReasonSegmentStart | kReasonTransmitProfileKnown;
      ensure_segment();
      PlanSegment& closing = segments.back();
      closing.profile = current_profile;
      closing.distance_m = segment_distance;
      closing.loss_db = segment_loss;
      closing.osnr_db = segment_osnr_inverse <= 0.0 ? 0.0 : -10.0 * std::log10(segment_osnr_inverse);
      closing.span_count = segment_span_count;
      closing.channel_runs = segment_channel_runs;
      closing.ended_by_regeneration = true;
      closing.regeneration_resource = ResourceKey::ForCrossConnect(cross_connect.id);
      segment_index += 1;
      regenerations += 1;
      if (!target_port->transmit_profile.HasValue() || !target_port->transmit_profile.value().has_value()) {
        return Failure(StatusCode::Internal, "plan build requires a transmit profile at a regeneration target");
      }
      current_profile = target_port->transmit_profile.value().value();
      PlanAssumption transmit_assumption;
      transmit_assumption.resource = ResourceKey::ForPort(target_port->key);
      transmit_assumption.field = "transmit_profile";
      transmit_assumption.value = current_profile.str();
      capability.push_back(std::move(transmit_assumption));
      mask = usable_mask(target_port->blocked_slots);
      segment_distance = 0;
      segment_loss = 0.0;
      segment_osnr_inverse = 0.0;
      segment_span_count = 0;
      segment_channel_runs = 0;
      segment_last_slot.reset();
    }

    push_step(StepKind::CrossConnect, ResourceKey::ForCrossConnect(cross_connect.id), segment_index, reasons,
              cross_connect.cost);
    total_cost += cross_connect.cost;
    note_domains(cross_connect.failure_domains);
    note_domains(target_port->failure_domains);
    total_cost += transition_node_cost(current_port, cross_connect.to);

    PlanAssumption operation_assumption;
    operation_assumption.resource = ResourceKey::ForCrossConnect(cross_connect.id);
    operation_assumption.field = "operation";
    operation_assumption.value = CrossConnectOpName(cross_connect.op);
    capability.push_back(std::move(operation_assumption));

    PlanAssumption target_spectrum_assumption;
    target_spectrum_assumption.resource = ResourceKey::ForPort(target_port->key);
    target_spectrum_assumption.field = "blocked_slots";
    target_spectrum_assumption.value = target_port->blocked_slots.value().ToHex();
    capability.push_back(std::move(target_spectrum_assumption));

    if (cross_connect.op != CrossConnectOp::Express) {
      push_step(StepKind::Port, ResourceKey::ForPort(target_port->key), segment_index,
                reasons | kReasonSpectrumAvailable, target_port->transit_cost);
      if (!(target_port->key.node == current_port.node)) {
        const NodeRecord* node = snapshot.FindNode(target_port->key.node);
        if (node != nullptr) {
          push_step(StepKind::Node, ResourceKey::ForNode(node->id), segment_index,
                    kReasonNotExcluded | kReasonAdminUp,
                    transition_node_cost(current_port, target_port->key));
          note_domains(node->failure_domains);
        }
      }
    }
    total_cost += target_port->transit_cost;
    current_port = cross_connect.to;
  }

  if (!(current_port == request.destination)) {
    return Failure(StatusCode::Internal, "plan build arc sequence does not end on the destination");
  }
  if (snapshot.FindPort(current_port) == nullptr) {
    return Failure(StatusCode::Internal, "plan build ended on a port with no record");
  }

  ensure_segment();
  {
    PlanSegment& trailing = segments.back();
    trailing.profile = current_profile;
    trailing.distance_m = segment_distance;
    trailing.loss_db = segment_loss;
    trailing.osnr_db = segment_osnr_inverse <= 0.0 ? 0.0 : -10.0 * std::log10(segment_osnr_inverse);
    trailing.span_count = segment_span_count;
    trailing.channel_runs = segment_channel_runs;
    trailing.ended_by_regeneration = false;
  }

  const ResourceKey destination_key = ResourceKey::ForPort(request.destination);
  if (steps.empty() || !(steps.back().resource == destination_key)) {
    push_step(StepKind::Port, destination_key, segment_index,
              kReasonNotExcluded | kReasonAdminUp | kReasonPortAdmitted | kReasonSpectrumAvailable, 0);
  }

  for (const auto& entry : domain_counts) {
    FailureDomainExposure exposure;
    exposure.id = entry.first;
    exposure.member_count = entry.second;
    const auto limit = request.constraints.max_members_per_failure_domain.find(entry.first);
    exposure.limit = limit == request.constraints.max_members_per_failure_domain.end() ? 0u : limit->second;
    exposures.push_back(std::move(exposure));
  }

  for (const PlanAssumption& assumption : capability) {
    if (assumption.resource.empty() || assumption.field.empty()) {
      return Failure(StatusCode::Internal, "plan build produced a capability assumption without a resource");
    }
  }
  for (const PlanAssumption& assumption : quality) {
    if (assumption.resource.empty() || assumption.field.empty()) {
      return Failure(StatusCode::Internal, "plan build produced a quality assumption without a resource");
    }
  }

  plan.steps = std::move(steps);
  plan.segments = std::move(segments);
  plan.reservations = std::move(reservations);
  plan.capability_assumptions = std::move(capability);
  plan.quality_assumptions = std::move(quality);
  plan.failure_domain_exposure = std::move(exposures);
  plan.total_cost = total_cost;
  plan.total_distance_m = 0;
  for (const PlanSegment& segment : plan.segments) plan.total_distance_m += segment.distance_m;
  plan.total_loss_db = 0.0;
  for (const PlanSegment& segment : plan.segments) plan.total_loss_db += segment.loss_db;
  plan.hops = static_cast<std::uint32_t>(arcs.size());
  plan.regenerations = regenerations;
  plan.Seal();
  if (out_digest != nullptr) *out_digest = plan.digest;
  return plan;
}

}  // namespace detail
}  // namespace opp
