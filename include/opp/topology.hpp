#pragma once

// Topology, capability and spectrum evidence.
//
// The snapshot is the immutable, canonically ordered set of records the planner
// reasons over. It is built through SnapshotBuilder, sealed by Build(), and from
// then on only exposes const access with index-based adjacency. No reference or
// iterator into a snapshot may be held across a mutation of the builder: the
// builder storage is append-only and is moved into the sealed snapshot once.

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "opp/evidence.hpp"
#include "opp/ids.hpp"
#include "opp/limits.hpp"
#include "opp/spectrum.hpp"
#include "opp/status.hpp"

namespace opp {

enum class NodeKind : std::uint8_t {
  Terminal = 0,
  ReconfigurableOadm = 1,
  OpticalCrossConnect = 2,
  Amplifier = 3,
  Regenerator = 4,
};

const char* NodeKindName(NodeKind kind) noexcept;
[[nodiscard]] bool ParseNodeKind(std::string_view text, NodeKind* out) noexcept;

enum class PortRole : std::uint8_t {
  Client = 0,
  Line = 1,
  Add = 2,
  Drop = 3,
  Express = 4,
  Monitor = 5,
};

const char* PortRoleName(PortRole role) noexcept;
[[nodiscard]] bool ParsePortRole(std::string_view text, PortRole* out) noexcept;

enum class CrossConnectOp : std::uint8_t {
  // Transparent: the channel is preserved and impairment accumulation continues.
  Express = 0,
  // Wavelength conversion without regeneration: the channel may change, the
  // transparent segment and its impairment budget continue.
  Convert = 1,
  // Optical-electrical-optical regeneration: a new transparent segment starts,
  // impairment accumulation resets and the channel may change.
  Regenerate = 2,
};

const char* CrossConnectOpName(CrossConnectOp op) noexcept;
[[nodiscard]] bool ParseCrossConnectOp(std::string_view text, CrossConnectOp* out) noexcept;

struct NodeRecord {
  NodeId id;
  NodeKind kind = NodeKind::Terminal;
  std::vector<FailureDomainId> failure_domains;
  std::uint64_t transit_cost = 0;
  Coverage coverage = Coverage::Complete;
  Evidence<AdminState> admin;
  SourceId source;
  Generation generation = 0;

  friend bool operator==(const NodeRecord&, const NodeRecord&) = default;
};

struct PortRecord {
  PortKey key;
  PortRole role = PortRole::Line;
  // Transmitter capability of this port. KNOWN(nullopt) means the port
  // explicitly has no transmitter, so no transparent segment may start here.
  // UNKNOWN means the capability was not published, which makes any segment
  // that would need it unprovable.
  Evidence<std::optional<ProfileId>> transmit_profile;
  // Slots that cannot be used at this port. UNKNOWN means the port spectrum
  // capability was not published.
  Evidence<SlotMask> blocked_slots;
  std::vector<FailureDomainId> failure_domains;
  std::uint64_t transit_cost = 0;
  Evidence<AdminState> admin;
  SourceId source;
  Generation generation = 0;

  friend bool operator==(const PortRecord&, const PortRecord&) = default;
};

struct SpanRecord {
  SpanId id;
  PortKey from;
  PortKey to;
  // When true the builder also creates the reverse arc over the same record.
  bool bidirectional = true;
  Evidence<std::uint64_t> length_m;
  Evidence<double> loss_db;
  // Declared optical signal-to-noise ratio contribution of this span, in dB, at
  // the segment reference. Aggregation across a segment uses the incoherent
  // noise-sum rule documented in the README.
  Evidence<double> osnr_db;
  Evidence<SlotMask> blocked_slots;
  std::vector<FailureDomainId> failure_domains;
  std::uint64_t cost = 0;
  Evidence<AdminState> admin;
  SourceId source;
  Generation generation = 0;

  friend bool operator==(const SpanRecord&, const SpanRecord&) = default;
};

struct CrossConnectRecord {
  CrossConnectId id;
  PortKey from;
  PortKey to;
  CrossConnectOp op = CrossConnectOp::Express;
  Evidence<SlotMask> blocked_slots;
  std::vector<FailureDomainId> failure_domains;
  std::uint64_t cost = 0;
  Evidence<AdminState> admin;
  SourceId source;
  Generation generation = 0;

  friend bool operator==(const CrossConnectRecord&, const CrossConnectRecord&) = default;
};

// Reach budget of a transmitter class. A transparent segment must satisfy every
// field that is KNOWN. An UNKNOWN field makes the segment unprovable rather than
// admissible.
struct ReachProfile {
  ProfileId id;
  Evidence<std::uint64_t> max_distance_m;
  Evidence<std::uint32_t> max_span_count;
  Evidence<double> max_loss_db;
  Evidence<double> min_osnr_db;
  SourceId source;
  Generation generation = 0;

  friend bool operator==(const ReachProfile&, const ReachProfile&) = default;
};

class TopologySnapshot;

struct SnapshotBuildOptions {
  // When true, spans and cross-connects may reference ports that have no
  // record. Those arcs become unprovable frontiers instead of a build error.
  bool allow_unresolved_references = true;
  // When true, a span whose two endpoints are the same port is rejected.
  bool reject_self_loops = true;
};

class SnapshotBuilder {
 public:
  SnapshotBuilder() = default;
  explicit SnapshotBuilder(SnapshotBuildOptions options) : options_(options) {}

  void SetId(SnapshotId id) { id_ = std::move(id); }
  void SetGeneration(Generation generation) { generation_ = generation; }
  void SetSpectrum(SpectrumModel spectrum) { spectrum_ = spectrum; }
  void SetBuildOptions(SnapshotBuildOptions options) { options_ = options; }

  [[nodiscard]] const SnapshotId& id() const noexcept { return id_; }
  [[nodiscard]] Generation generation() const noexcept { return generation_; }
  [[nodiscard]] const SpectrumModel& spectrum() const noexcept { return spectrum_; }

  Status AddSource(SourceRecord record);
  Status AddNode(NodeRecord record);
  Status AddPort(PortRecord record);
  Status AddSpan(SpanRecord record);
  Status AddCrossConnect(CrossConnectRecord record);
  Status AddReachProfile(ReachProfile record);

  [[nodiscard]] std::size_t node_count() const noexcept { return nodes_.size(); }
  [[nodiscard]] std::size_t port_count() const noexcept { return ports_.size(); }
  [[nodiscard]] std::size_t span_count() const noexcept { return spans_.size(); }
  [[nodiscard]] std::size_t cross_connect_count() const noexcept { return cross_connects_.size(); }

  Expected<TopologySnapshot> Build();

 private:
  SnapshotId id_;
  Generation generation_ = 0;
  SpectrumModel spectrum_{};
  SnapshotBuildOptions options_{};

  std::vector<SourceRecord> sources_;
  std::vector<NodeRecord> nodes_;
  std::vector<PortRecord> ports_;
  std::vector<SpanRecord> spans_;
  std::vector<CrossConnectRecord> cross_connects_;
  std::vector<ReachProfile> profiles_;
  bool built_ = false;
};

// A directed span arc. A bidirectional span record produces two arcs that both
// point at the same record; the reversed flag says which endpoint is the tail.
struct SpanArc {
  std::uint32_t span_index = 0;
  bool reversed = false;
};

// Whether a snapshot is the evidence a live producer published, or a copy a
// service restored from persistence. A restored copy is never fresh: it may be
// arbitrarily behind the producers it came from, so planning against it is
// refused unless the caller explicitly accepts it.
enum class EvidenceFreshness : std::uint8_t {
  Fresh = 0,
  Restored = 1,
};

const char* EvidenceFreshnessName(EvidenceFreshness freshness) noexcept;

class TopologySnapshot {
 public:
  TopologySnapshot() = default;

  [[nodiscard]] const SnapshotId& id() const noexcept { return id_; }
  [[nodiscard]] Generation generation() const noexcept { return generation_; }
  [[nodiscard]] const SpectrumModel& spectrum() const noexcept { return spectrum_; }
  [[nodiscard]] const Digest256& digest() const noexcept { return digest_; }

  [[nodiscard]] const std::vector<SourceRecord>& sources() const noexcept { return sources_; }
  [[nodiscard]] const std::vector<NodeRecord>& nodes() const noexcept { return nodes_; }
  [[nodiscard]] const std::vector<PortRecord>& ports() const noexcept { return ports_; }
  [[nodiscard]] const std::vector<SpanRecord>& spans() const noexcept { return spans_; }
  [[nodiscard]] const std::vector<CrossConnectRecord>& cross_connects() const noexcept { return cross_connects_; }
  [[nodiscard]] const std::vector<ReachProfile>& reach_profiles() const noexcept { return profiles_; }

  [[nodiscard]] const NodeRecord* FindNode(const NodeId& id) const;
  [[nodiscard]] const PortRecord* FindPort(const PortKey& key) const;
  [[nodiscard]] const ReachProfile* FindReachProfile(const ProfileId& id) const;
  [[nodiscard]] std::optional<std::uint32_t> PortIndex(const PortKey& key) const;
  [[nodiscard]] std::optional<std::uint32_t> NodeIndex(const NodeId& id) const;

  [[nodiscard]] const std::vector<SpanArc>& OutgoingSpanArcs(std::uint32_t port_index) const;
  [[nodiscard]] const std::vector<std::uint32_t>& OutgoingCrossConnects(std::uint32_t port_index) const;

  // Generation published by a source, or 0 when the source is not present.
  [[nodiscard]] Generation SourceGeneration(const SourceId& id) const;
  [[nodiscard]] bool HasSource(const SourceId& id) const;

  // Resource identities whose records disagreed across sources or duplicates.
  [[nodiscard]] bool IsConflicted(const ResourceKey& key) const;
  [[nodiscard]] const std::vector<ResourceKey>& conflicted_resources() const noexcept { return conflicted_; }

  // Records referenced by an arc but absent from the snapshot.
  [[nodiscard]] const std::vector<ResourceKey>& unresolved_references() const noexcept { return unresolved_; }

  // True when every contributing source declared itself exhaustive and no
  // unresolved reference exists.
  [[nodiscard]] bool coverage_complete() const noexcept { return coverage_complete_; }

  // Number of arcs that were dropped because an endpoint had no record. A search
  // standing on the port returns true from HasUnresolvedArcs and must treat any
  // conclusion it reaches there as unprovable.
  [[nodiscard]] bool HasUnresolvedArcs(std::uint32_t port_index) const {
    return port_index < unresolved_at_port_.size() && unresolved_at_port_[port_index] != 0;
  }

  // Total number of directed arcs (span arcs plus cross-connects).
  [[nodiscard]] std::uint64_t ArcCount() const noexcept;

  [[nodiscard]] EvidenceFreshness freshness() const noexcept { return freshness_; }
  [[nodiscard]] const IncarnationId& restored_from_incarnation() const noexcept {
    return restored_from_incarnation_;
  }
  [[nodiscard]] Epoch restored_from_epoch() const noexcept { return restored_from_epoch_; }

  // Marks a snapshot as restored from persistence. Deliberately a named
  // mutator: nothing else in this runtime may quietly change freshness, and the
  // marker is not part of the content digest.
  void MarkRestored(const IncarnationId& producer, Epoch epoch);

 private:
  friend class SnapshotBuilder;

  SnapshotId id_;
  Generation generation_ = 0;
  SpectrumModel spectrum_{};
  Digest256 digest_{};

  std::vector<SourceRecord> sources_;
  std::vector<NodeRecord> nodes_;
  std::vector<PortRecord> ports_;
  std::vector<SpanRecord> spans_;
  std::vector<CrossConnectRecord> cross_connects_;
  std::vector<ReachProfile> profiles_;

  std::vector<ResourceKey> conflicted_;
  std::vector<ResourceKey> unresolved_;
  bool coverage_complete_ = true;
  EvidenceFreshness freshness_ = EvidenceFreshness::Fresh;
  IncarnationId restored_from_incarnation_{};
  Epoch restored_from_epoch_ = 0;

  // Adjacency, indexed by port index. Span arcs are sorted by
  // (span id, reversed, target port) and cross-connects by (id).
  std::vector<std::vector<SpanArc>> span_arcs_;
  std::vector<std::vector<std::uint32_t>> out_cross_connects_;
  std::vector<std::uint32_t> unresolved_at_port_;
};

// Computes the digest of a snapshot from its canonical text encoding.
[[nodiscard]] Digest256 ComputeSnapshotDigest(const TopologySnapshot& snapshot);

// Digest of the canonical records contributed by one evidence source. Recorded
// in a plan binding so that a consumer can tell which source changed even when
// the aggregate generation did not move.
[[nodiscard]] Digest256 SourceContributionDigest(const TopologySnapshot& snapshot, const SourceId& source);

}  // namespace opp
