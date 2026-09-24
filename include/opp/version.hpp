#pragma once

// Version and format-revision constants for the Optical Path Planner runtime.
//
// Every externally visible artifact (snapshot text, plan artifact, wire frame,
// persisted store entry) carries an explicit format revision. A reader that does
// not recognise a revision reports UNSUPPORTED instead of guessing.

#include <cstdint>

namespace opp {

inline constexpr int kVersionMajor = 1;
inline constexpr int kVersionMinor = 0;
inline constexpr int kVersionPatch = 0;

// Revision of the planning rules. It participates in the plan digest so that a
// plan produced by a different rule revision can never compare equal to one
// produced here.
inline constexpr std::uint32_t kPlanningRuleVersion = 1;

// On-disk / on-wire format revisions.
inline constexpr std::uint32_t kSnapshotFormatVersion = 1;
inline constexpr std::uint32_t kPlanFormatVersion = 1;
inline constexpr std::uint32_t kStoreFormatVersion = 1;
inline constexpr std::uint32_t kProtocolVersion = 1;

// Human readable version string, e.g. "1.0.0".
const char* VersionString();

// Library name reported by the CLI and the service handshake.
const char* LibraryName();

// Compiler/standard identification captured at build time. Diagnostics only; it
// never participates in any digest.
const char* BuildIdentification();

}  // namespace opp
