#pragma once

// Umbrella header for the Optical Path Planner runtime.
//
// This library computes candidate routes through reconfigurable optical
// resources from explicit evidence. It is a planner, not an authority: it never
// activates a path, reserves spectrum, mutates a transceiver or programs
// hardware, and it owns none of the evidence it reasons over.

#include "opp/canonical.hpp"
#include "opp/constraints.hpp"
#include "opp/evidence.hpp"
#include "opp/fileio.hpp"
#include "opp/ids.hpp"
#include "opp/limits.hpp"
#include "opp/plan.hpp"
#include "opp/planner.hpp"
#include "opp/proto.hpp"
#include "opp/request.hpp"
#include "opp/request_io.hpp"
#include "opp/result.hpp"
#include "opp/service.hpp"
#include "opp/sha256.hpp"
#include "opp/snapshot_io.hpp"
#include "opp/spectrum.hpp"
#include "opp/synthetic.hpp"
#include "opp/status.hpp"
#include "opp/store.hpp"
#include "opp/topology.hpp"
#include "opp/validate.hpp"
#include "opp/version.hpp"

namespace opp {

// Library self-check: SHA-256 vectors, canonical round-trips, spectrum rules and
// store codec invariants. Returns a status whose detail names the first failure.
[[nodiscard]] Status SelfTest();

}  // namespace opp
