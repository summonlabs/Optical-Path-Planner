#pragma once

// Deterministic synthetic topology generation.
//
// This is a test, benchmark and demonstration fixture, not an evidence source.
// Everything it produces is SYNTHETIC: no field in the generated snapshot is a
// measurement of any real link, and no output of this runtime should be read as
// a statement about real optical hardware. The generator is reproducible: the
// same options always produce byte-identical snapshot text.

#include <cstdint>
#include <string>

#include "opp/topology.hpp"

namespace opp {

struct SyntheticOptions {
  std::uint64_t seed = 1;
  std::uint32_t node_count = 8;
  // Target number of distinct neighbours per node in the generated graph.
  std::uint32_t degree = 3;
  std::uint16_t slot_count = 32;
  GridKind grid = GridKind::Fixed50GHz;
  // Client access ports per node.
  std::uint32_t client_ports = 2;
  // When true, every fifth node regenerates instead of switching transparently.
  bool include_regenerators = true;
  // Fraction of slots blocked per span, expressed as "one slot in every N".
  std::uint32_t slot_blocking_one_in = 8;
  // When false, span OSNR is left unpublished, which makes every route
  // unprovable rather than infeasible. Used to exercise the knowledge frontier.
  bool publish_osnr = true;
  // When false, span length is left unpublished.
  bool publish_length = true;
  Generation generation = 1;
  std::string id = "synthetic";
  std::string source_id = "synthetic-generator";
};

// Builds the snapshot. node_count must be at least 2 and at most kMaxGeneratedNodes.
[[nodiscard]] Expected<TopologySnapshot> GenerateSyntheticTopology(const SyntheticOptions& options);

// A small, fixed, hand-shaped topology used by the examples and the quickstart.
// It is deliberately tiny so a reader can verify the expected answer by hand.
[[nodiscard]] Expected<TopologySnapshot> BuildExampleTopology();

}  // namespace opp
