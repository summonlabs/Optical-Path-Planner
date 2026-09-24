#pragma once

// Shared fixtures for the test suites. Every helper here is deterministic: the
// same call always builds the same bytes, so a failing case is reproducible
// from its name alone.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "opp/opp.hpp"

namespace opp_test {

// Creates (or recreates) a directory under the system temporary directory. The
// name is derived from the case name so parallel suites cannot collide.
std::string FreshTempDir(const std::string& name);

// Removes a directory tree, ignoring absence.
void RemoveTree(const std::string& path);

// Builds a fully published snapshot: every field is KNOWN, every node covers its
// whole adjacency, and no record disagrees with another. This is the fixture the
// differential oracle compares against.
opp::Expected<opp::TopologySnapshot> BuildCompleteSnapshot(std::uint64_t seed, std::uint32_t node_count,
                                                           std::uint16_t slot_count,
                                                           std::uint32_t slot_blocking_one_in);

// A snapshot identical to BuildCompleteSnapshot except that the named span's OSNR
// is not published.
opp::Expected<opp::TopologySnapshot> BuildSnapshotWithUnknownOsnr(std::uint64_t seed, std::uint32_t node_count);

// A snapshot whose only route is through a node that declares partial coverage.
opp::Expected<opp::TopologySnapshot> BuildPartialCoverageSnapshot();

// A minimal two-node snapshot with a single direct span.
opp::Expected<opp::TopologySnapshot> BuildTwoNodeSnapshot(opp::Evidence<double> span_osnr);

// A linear chain of nodes. Each node has one client ingress, one client egress and
// a west/east line pair, with express cross-connects between them. The branching
// factor is deliberately small so the reference solver can enumerate every
// port-simple route. Nodes whose index is divisible by four regenerate.
opp::Expected<opp::TopologySnapshot> BuildChainSnapshot(std::uint32_t node_count, std::uint16_t slot_count,
                                                        std::uint64_t seed, bool ring);

// Deterministic pseudo-random helper shared by the suites (splitmix64).
class Random {
 public:
  explicit Random(std::uint64_t seed) : state_(seed) {}
  std::uint64_t Next();
  std::uint32_t Below(std::uint32_t bound);
  double UnitDouble();

 private:
  std::uint64_t state_;
};

}  // namespace opp_test
