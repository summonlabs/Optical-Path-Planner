#pragma once

// Canonical text encoding of topology snapshots.
//
// One line-oriented grammar serves three purposes: it is the human-authorable
// ingestion format, the byte string the snapshot digest is computed over, and the
// payload of the ingest message. A parsed snapshot re-encodes to exactly the
// bytes it was parsed from, which is what makes the digest meaningful.

#include <string>
#include <string_view>

#include "opp/status.hpp"
#include "opp/topology.hpp"

namespace opp {

inline constexpr const char* kSnapshotMagic = "OPP-SNAPSHOT";
inline constexpr const char* kSnapshotDigestDomain = "OPP-SNAPSHOT-v1";

// Canonical text of a sealed snapshot. Deterministic: identical snapshots produce
// identical bytes on every platform.
[[nodiscard]] std::string SnapshotToText(const TopologySnapshot& snapshot);

// Parses canonical snapshot text. The result is sealed (digest computed) and
// ready to plan against.
[[nodiscard]] Expected<TopologySnapshot> ParseSnapshotText(std::string_view text);

// Reads a snapshot file with a bounded size check.
[[nodiscard]] Expected<TopologySnapshot> LoadSnapshotFile(const std::string& path);

// Writes canonical snapshot text atomically (temporary file plus rename).
[[nodiscard]] Status SaveSnapshotFile(const std::string& path, const TopologySnapshot& snapshot);

}  // namespace opp
