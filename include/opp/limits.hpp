#pragma once

// Hard bounds applied to every externally derived quantity.
//
// The planner is a consumer of evidence supplied by other runtimes. All of that
// evidence is untrusted input: sizes, counts and identifiers are validated
// against these bounds before anything is allocated, and every size computation
// derived from input uses checked arithmetic.

#include <cstddef>
#include <cstdint>

namespace opp {

// Topology snapshot bounds.
inline constexpr std::uint32_t kMaxNodes = 4096;
inline constexpr std::uint32_t kMaxPorts = 16384;
inline constexpr std::uint32_t kMaxSpans = 32768;
inline constexpr std::uint32_t kMaxCrossConnects = 65536;
inline constexpr std::uint32_t kMaxReachProfiles = 256;
inline constexpr std::uint32_t kMaxSources = 64;
inline constexpr std::uint32_t kMaxFailureDomains = 4096;
inline constexpr std::uint32_t kMaxDomainsPerResource = 16;
inline constexpr std::uint32_t kMaxIdLength = 96;
inline constexpr std::uint32_t kMaxSnapshotTextBytes = 64u * 1024u * 1024u;
inline constexpr std::uint32_t kMaxTextLineBytes = 8192;

// Spectrum model bounds.
inline constexpr std::uint16_t kMaxSpectrumSlots = 256;

// Planning request bounds.
inline constexpr std::uint32_t kMaxCandidates = 16;
inline constexpr std::uint32_t kMaxRequestedRegenerations = 64;
inline constexpr std::uint32_t kMaxRequestedHops = 512;
inline constexpr std::uint32_t kDefaultMaxHops = 128;
inline constexpr std::uint32_t kDefaultMaxRegenerations = 8;
inline constexpr std::uint32_t kMaxExclusionEntries = 4096;
inline constexpr std::uint32_t kMaxDomainMemberLimits = 1024;
inline constexpr std::uint32_t kMaxRequiredGenerations = 64;

// Search bounds. These are ceilings, not timeouts: a search that reaches a
// ceiling stops with an explicit truncation marker and can never report
// INFEASIBLE or claim optimality.
inline constexpr std::uint64_t kMaxSearchExpansionsCeiling = 20000000ull;
inline constexpr std::uint64_t kMaxSearchLabelsCeiling = 40000000ull;
inline constexpr std::uint64_t kDefaultSearchExpansions = 400000ull;
inline constexpr std::uint64_t kDefaultSearchLabels = 800000ull;

// Explanation bounds (witness lists are capped and deduplicated).
inline constexpr std::uint32_t kMaxWitnessEntries = 64;
inline constexpr std::uint32_t kMaxExplainReasons = 64;

// Persistence bounds.
inline constexpr std::uint32_t kMaxStoredPlans = 100000;
inline constexpr std::uint64_t kMaxPlanArtifactBytes = 8ull * 1024ull * 1024ull;
inline constexpr std::uint64_t kMaxStoreFileBytes = 16ull * 1024ull * 1024ull;

// Service bounds.
inline constexpr std::uint32_t kMaxFrameBytes = 16u * 1024u * 1024u;
inline constexpr std::uint32_t kMaxFrameHeaderBytes = 64;
inline constexpr std::uint32_t kMaxServiceConnections = 64;
inline constexpr std::uint32_t kMaxPendingCancellations = 4096;
inline constexpr std::uint32_t kDefaultServiceBacklog = 32;

// Text generation limit (defensive; a topology larger than this is refused).
inline constexpr std::uint32_t kMaxGeneratedNodes = 4096;

}  // namespace opp
