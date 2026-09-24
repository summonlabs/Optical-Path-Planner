#pragma once

// Strongly typed identities.
//
// Every identity in the model is a distinct type even when the underlying
// representation is the same string. Mixing a port id with a node id is a
// compile error rather than a silent mis-plan.

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>

#include "opp/limits.hpp"
#include "opp/status.hpp"

namespace opp {

// Identifier text alphabet: ASCII alphanumerics plus '_', '-', '.', ':', '/', '@'
// and '+'. The first character must be alphanumeric. Length is bounded by
// kMaxIdLength. This grammar is intentionally narrow so that identifiers are
// safe to embed in the canonical encodings and in text files.
[[nodiscard]] bool IsValidIdText(std::string_view text) noexcept;

namespace tag {
struct NodeTag {};
struct PortTag {};
struct SpanTag {};
struct CrossConnectTag {};
struct FailureDomainTag {};
struct ProfileTag {};
struct SourceTag {};
struct RequestTag {};
struct SnapshotTag {};
}  // namespace tag

template <class Tag>
class StrongId {
 public:
  StrongId() = default;

  // Parses and validates identifier text.
  static Expected<StrongId> Parse(std::string_view text) {
    if (!IsValidIdText(text)) {
      return Failure(StatusCode::InvalidArgument,
                     "identifier is empty, too long, or contains characters outside the identity alphabet");
    }
    StrongId id;
    id.value_.assign(text);
    return id;
  }

  // Precondition: IsValidIdText(text). Used for compile-time literals in tests
  // and for values that were validated on an earlier path.
  static StrongId Trusted(std::string_view text) {
    StrongId id;
    id.value_.assign(text);
    return id;
  }

  [[nodiscard]] const std::string& str() const noexcept { return value_; }
  [[nodiscard]] bool empty() const noexcept { return value_.empty(); }
  [[nodiscard]] std::string_view view() const noexcept { return value_; }

  friend bool operator==(const StrongId&, const StrongId&) = default;
  friend auto operator<=>(const StrongId&, const StrongId&) = default;

 private:
  std::string value_;
};

using NodeId = StrongId<tag::NodeTag>;
using PortId = StrongId<tag::PortTag>;
using SpanId = StrongId<tag::SpanTag>;
using CrossConnectId = StrongId<tag::CrossConnectTag>;
using FailureDomainId = StrongId<tag::FailureDomainTag>;
using ProfileId = StrongId<tag::ProfileTag>;
using SourceId = StrongId<tag::SourceTag>;
using RequestId = StrongId<tag::RequestTag>;
using SnapshotId = StrongId<tag::SnapshotTag>;

// Monotonic evidence generation published by an evidence source.
using Generation = std::uint64_t;

// Service lifetime counters. An epoch strictly increases across restarts of a
// stateful service; an incarnation identifies one process lifetime.
using Epoch = std::uint64_t;

struct PortKey {
  NodeId node;
  PortId port;

  friend bool operator==(const PortKey&, const PortKey&) = default;
  friend auto operator<=>(const PortKey&, const PortKey&) = default;

  [[nodiscard]] std::string CanonicalText() const;
};

struct Digest256 {
  std::array<std::uint8_t, 32> bytes{};

  friend bool operator==(const Digest256&, const Digest256&) = default;
  friend auto operator<=>(const Digest256&, const Digest256&) = default;

  [[nodiscard]] bool IsZero() const noexcept;
  [[nodiscard]] std::string ToHex() const;
  static Expected<Digest256> FromHex(std::string_view hex);
};

struct IncarnationId {
  std::array<std::uint8_t, 16> bytes{};

  friend bool operator==(const IncarnationId&, const IncarnationId&) = default;
  friend auto operator<=>(const IncarnationId&, const IncarnationId&) = default;

  [[nodiscard]] bool IsZero() const noexcept;
  [[nodiscard]] std::string ToHex() const;
  static Expected<IncarnationId> FromHex(std::string_view hex);
};

// Kinds of resources that can appear in a plan, in an exclusion list or in a
// witness. Enumeration order is part of the canonical encoding: never reorder.
enum class ResourceKind : std::uint8_t {
  Node = 0,
  Port = 1,
  Span = 2,
  CrossConnect = 3,
  FailureDomain = 4,
  ReachProfile = 5,
  Channel = 6,
  Source = 7,
};

const char* ResourceKindName(ResourceKind kind) noexcept;

// A resource identified by kind plus its canonical text form. Using the text
// form keeps witnesses, exclusions and plan steps comparable and serialisable
// without a variant type.
class ResourceKey {
 public:
  ResourceKey() = default;
  ResourceKey(ResourceKind kind, std::string text) : kind_(kind), text_(std::move(text)) {}

  static ResourceKey ForNode(const NodeId& id);
  static ResourceKey ForPort(const PortKey& key);
  static ResourceKey ForSpan(const SpanId& id);
  static ResourceKey ForCrossConnect(const CrossConnectId& id);
  static ResourceKey ForFailureDomain(const FailureDomainId& id);
  static ResourceKey ForReachProfile(const ProfileId& id);
  static ResourceKey ForChannel(std::uint16_t first_slot, std::uint16_t width_slots);
  static ResourceKey ForSource(const SourceId& id);

  [[nodiscard]] ResourceKind kind() const noexcept { return kind_; }
  [[nodiscard]] const std::string& text() const noexcept { return text_; }
  [[nodiscard]] bool empty() const noexcept { return text_.empty(); }

  friend bool operator==(const ResourceKey&, const ResourceKey&) = default;
  friend auto operator<=>(const ResourceKey&, const ResourceKey&) = default;

 private:
  ResourceKind kind_ = ResourceKind::Node;
  std::string text_;
};

// Parses the canonical "kind:text" spelling used by ResourceKey.
[[nodiscard]] std::string ResourceKeyToString(const ResourceKey& key);
[[nodiscard]] Expected<ResourceKey> ResourceKeyFromString(std::string_view text);

}  // namespace opp

namespace std {

template <class Tag>
struct hash<opp::StrongId<Tag>> {
  std::size_t operator()(const opp::StrongId<Tag>& id) const noexcept {
    return std::hash<std::string_view>{}(id.view());
  }
};

template <>
struct hash<opp::PortKey> {
  std::size_t operator()(const opp::PortKey& key) const noexcept {
    std::size_t h = std::hash<std::string_view>{}(key.node.view());
    h ^= std::hash<std::string_view>{}(key.port.view()) + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
    return h;
  }
};

}  // namespace std
