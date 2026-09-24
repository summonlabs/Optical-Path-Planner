#include "opp/ids.hpp"

#include <algorithm>
#include <string>

namespace opp {

bool IsValidIdText(std::string_view text) noexcept {
  if (text.empty() || text.size() > kMaxIdLength) return false;
  const auto is_alnum = [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  };
  if (!is_alnum(text[0])) return false;
  for (char c : text) {
    const bool ok = is_alnum(c) || c == '_' || c == '-' || c == '.' || c == ':' || c == '/' || c == '@' || c == '+';
    if (!ok) return false;
  }
  return true;
}

namespace {

const char* const kHexDigits = "0123456789abcdef";

int HexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

template <std::size_t N>
std::string ToHexImpl(const std::array<std::uint8_t, N>& bytes) {
  std::string out;
  out.reserve(N * 2);
  for (std::uint8_t byte : bytes) {
    out.push_back(kHexDigits[(byte >> 4) & 0x0fu]);
    out.push_back(kHexDigits[byte & 0x0fu]);
  }
  return out;
}

template <std::size_t N>
bool FromHexImpl(std::string_view hex, std::array<std::uint8_t, N>* out) {
  if (hex.size() != N * 2) return false;
  for (std::size_t i = 0; i < N; ++i) {
    const int high = HexValue(hex[i * 2]);
    const int low = HexValue(hex[i * 2 + 1]);
    if (high < 0 || low < 0) return false;
    (*out)[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

template <std::size_t N>
bool IsZeroImpl(const std::array<std::uint8_t, N>& bytes) {
  for (std::uint8_t byte : bytes) {
    if (byte != 0) return false;
  }
  return true;
}

}  // namespace

std::string PortKey::CanonicalText() const {
  return node.str() + ":" + port.str();
}

bool Digest256::IsZero() const noexcept { return IsZeroImpl(bytes); }

std::string Digest256::ToHex() const { return ToHexImpl(bytes); }

Expected<Digest256> Digest256::FromHex(std::string_view hex) {
  Digest256 digest;
  if (!FromHexImpl(hex, &digest.bytes)) {
    return Failure(StatusCode::MalformedInput, "digest hex must be 64 lowercase or uppercase hex characters");
  }
  return digest;
}

bool IncarnationId::IsZero() const noexcept { return IsZeroImpl(bytes); }

std::string IncarnationId::ToHex() const { return ToHexImpl(bytes); }

Expected<IncarnationId> IncarnationId::FromHex(std::string_view hex) {
  IncarnationId incarnation;
  if (!FromHexImpl(hex, &incarnation.bytes)) {
    return Failure(StatusCode::MalformedInput, "incarnation hex must be 32 hexadecimal characters");
  }
  return incarnation;
}

const char* ResourceKindName(ResourceKind kind) noexcept {
  switch (kind) {
    case ResourceKind::Node:
      return "node";
    case ResourceKind::Port:
      return "port";
    case ResourceKind::Span:
      return "span";
    case ResourceKind::CrossConnect:
      return "crossconnect";
    case ResourceKind::FailureDomain:
      return "domain";
    case ResourceKind::ReachProfile:
      return "profile";
    case ResourceKind::Channel:
      return "channel";
    case ResourceKind::Source:
      return "source";
  }
  return "unknown";
}

ResourceKey ResourceKey::ForNode(const NodeId& id) { return ResourceKey(ResourceKind::Node, id.str()); }

ResourceKey ResourceKey::ForPort(const PortKey& key) {
  return ResourceKey(ResourceKind::Port, key.CanonicalText());
}

ResourceKey ResourceKey::ForSpan(const SpanId& id) { return ResourceKey(ResourceKind::Span, id.str()); }

ResourceKey ResourceKey::ForCrossConnect(const CrossConnectId& id) {
  return ResourceKey(ResourceKind::CrossConnect, id.str());
}

ResourceKey ResourceKey::ForFailureDomain(const FailureDomainId& id) {
  return ResourceKey(ResourceKind::FailureDomain, id.str());
}

ResourceKey ResourceKey::ForReachProfile(const ProfileId& id) {
  return ResourceKey(ResourceKind::ReachProfile, id.str());
}

ResourceKey ResourceKey::ForSource(const SourceId& id) { return ResourceKey(ResourceKind::Source, id.str()); }

ResourceKey ResourceKey::ForChannel(std::uint16_t first_slot, std::uint16_t width_slots) {
  return ResourceKey(ResourceKind::Channel,
                     std::to_string(static_cast<unsigned>(first_slot)) + "+" +
                         std::to_string(static_cast<unsigned>(width_slots)));
}

std::string ResourceKeyToString(const ResourceKey& key) {
  return std::string(ResourceKindName(key.kind())) + ":" + key.text();
}

Expected<ResourceKey> ResourceKeyFromString(std::string_view text) {
  const std::size_t separator = text.find(':');
  if (separator == std::string_view::npos || separator == 0) {
    return Failure(StatusCode::MalformedInput, "resource key must be spelled kind:text");
  }
  const std::string_view kind_text = text.substr(0, separator);
  const std::string_view body = text.substr(separator + 1);
  if (body.empty()) {
    return Failure(StatusCode::MalformedInput, "resource key body must not be empty");
  }
  static const struct {
    const char* name;
    ResourceKind kind;
  } kKinds[] = {
      {"node", ResourceKind::Node},         {"port", ResourceKind::Port},
      {"span", ResourceKind::Span},         {"crossconnect", ResourceKind::CrossConnect},
      {"domain", ResourceKind::FailureDomain}, {"profile", ResourceKind::ReachProfile},
      {"channel", ResourceKind::Channel},   {"source", ResourceKind::Source},
  };
  for (const auto& entry : kKinds) {
    if (kind_text == entry.name) {
      return ResourceKey(entry.kind, std::string(body));
    }
  }
  return Failure(StatusCode::MalformedInput, "unrecognised resource kind '" + std::string(kind_text) + "'");
}

}  // namespace opp
