# Optical Path Planner

Optical Path Planner is a deterministic, vendor-neutral planner that computes candidate routes
through reconfigurable optical resources from explicit topology, capability, spectrum, quality,
policy and authority evidence.

The question it answers is narrow and deliberate: *given the optical fabric as it is known at this
exact generation, which end-to-end optical path satisfies the declared constraints, and when is the
answer impossible versus merely indeterminate because evidence is missing?*

Planner output is a recommendation. It is not execution authority. This runtime never activates a
path, reserves wavelength resources, mutates a transceiver or programs optical hardware, and it owns
none of the evidence it reasons over.

## Outcomes

Every planning request returns exactly one of four verdicts, plus two boundary outcomes for requests
that were never searched.

| Outcome | Meaning |
| --- | --- |
| `FEASIBLE` | At least one proven candidate satisfies every declared constraint. |
| `INFEASIBLE` | Complete enough knowledge proves that no route can satisfy the constraints. |
| `INDETERMINATE` | Missing, stale or conflicting evidence prevents proof either way. |
| `UNSUPPORTED` | The requested semantics are outside the modelled capability surface. |
| `REFUSED` | The request failed structural validation before any search started. |
| `CANCELLED` | The caller cancelled; no candidate is published. |

Precedence is fixed and documented in `include/opp/planner.hpp`: structural validation, then the
modelled capability surface, then evidence freshness, then the search. A stale or restored snapshot
can never yield `FEASIBLE`, and a search that reaches a knowledge frontier or a configured bound can
never report `INFEASIBLE`.

## Evidence model

Facts are tri-state. A value is `KNOWN`, `UNKNOWN` (never published) or `CONFLICTING` (two records
disagree). The planner never substitutes a default for `UNKNOWN` and never picks a winner for
`CONFLICTING`; both make a conclusion unprovable, which is reported as `INDETERMINATE`.

* **Nodes** carry a kind, failure domains, a transit cost, an administrative state, and a coverage
  declaration. A node that publishes only part of its adjacency (`partial`) is a knowledge frontier.
* **Ports** carry a role, an optional transmit reach profile (`none` when the port explicitly has no
  transmitter), a blocked-slot set, failure domains, a transit cost and an administrative state.
* **Spans** are directed, optionally mirrored, and carry length, loss, a declared OSNR contribution,
  a blocked-slot set, failure domains, a policy cost and an administrative state.
* **Cross-connects** are directed internal edges with one of three modelled operations: `express`
  (transparent), `convert` (the channel may change, the transparent segment continues) and
  `regenerate` (a new transparent segment starts and impairment accumulation resets).
* **Reach profiles** bound a transparent segment: maximum distance, maximum span count, maximum loss
  and minimum OSNR. A segment must satisfy every field that is `KNOWN`; an `UNKNOWN` field makes the
  segment unprovable rather than admissible.
* **Snapshots** carry an id, a generation, a per-source generation list, and a content digest. A
  snapshot that a service restored from persistence is marked `restored` and is never treated as
  fresh unless the caller explicitly accepts restored evidence.

### Spectrum

The spectrum model is a grid of equally wide slots: a fixed 50 GHz grid where every channel is one
slot, or a flexible 12.5 GHz grid where a channel spans one or more contiguous slots. Nothing in this
runtime asserts a physical frequency plan; a request names a channel width in slots and the search
tracks which starting slots remain usable. Within one wavelength run the channel must be constant, so
the running usable set is the intersection of every port, cross-connect and span mask along that run.
The channel reported for a span is the lowest-indexed slot still available, which makes the choice
deterministic.

### Quality accumulation

Inside one transparent segment, distance and loss add, and OSNR aggregates with the incoherent
noise-sum rule over the declared per-span contributions. These are modelling rules applied to
declared evidence; they are not measurements, and the runtime never claims to have measured a link.

## Search

The planner runs a deterministic Pareto label-correcting best-first search over port states. Each
label carries the resource vector (cost, distance, loss, inverse OSNR, span count, hops,
regenerations) and the running set of usable channel starts. A label is discarded only when another
retained label at the same port and reach profile is at least as good in every dimension and is at
least as provable; that relation is extension monotone, so pruning never removes an optimum.

Routes are port-simple. Removing a cycle from a walk can only lower its cost and its resource vector
and can only widen its usable channel set, so the optimum over all walks is itself port-simple;
enforcing this removes an unbounded family of useless labels without losing an optimum.

Candidates are ordered by total policy cost, then hop count, then regeneration count, then the
lexicographic resource sequence. `optimality_proven` is true only when the search proved its bound
and the snapshot claims complete coverage.

`max_candidates` with `disjointness = none` returns the distinct Pareto-retained candidates, which
may be fewer than requested: a route that is worse in every dimension is not a useful alternative.
With `disjointness` set to `node`, `span` or `domain`, the planner re-plans once per requested
candidate, adding the resources of every accepted candidate to the exclusion set. The candidates are
then pairwise disjoint by construction and each one is the optimum given the resources the earlier
candidates took.

## Plan artifacts

A sealed plan contains:

* the ordered resources with, for each step, the typed eligibility reasons that made it admissible;
* the transparent segments with their profile, accumulators and span uses;
* the spectrum the route would require, span by span (a requirement, never a reservation);
* the capability assumptions (transmit profiles, cross-connect operations, spectrum capabilities) and
  the quality assumptions (length, loss, OSNR, reach limits) the plan relies on;
* the failure-domain exposure with member counts and any declared limit;
* every bound source generation with a per-source contribution digest, plus the snapshot id,
  generation, content digest and planning rule revision;
* a SHA-256 seal over the canonical artifact text.

Staleness is enforced by construction: `ValidatePlanBindings` rejects a plan as soon as any bound
source generation no longer matches the current evidence, and `RevalidatePlan` additionally
re-derives every eligibility decision against the current snapshot. A plan restored from disk is
never accepted against restored evidence.

## Persistence

Plan artifacts are stored content-addressed: the file name is the digest of the artifact it holds.
Writes land in a temporary file that is flushed to the device and renamed into place, so a reader
never observes a partially written artifact. Every read re-verifies the artifact seal and the file
checksum; corruption, truncation, wrong magic and revision drift are reported as distinct failures
and nothing is silently repaired or overwritten. The store is bounded and refuses to grow past its
capacity instead of evicting artifacts behind the caller's back. Stale temporary files left by an
interrupted write are the only thing the store repairs, and only on open.

## Inspection service

`oppd` is a loopback-only inspection service that holds at most one sealed snapshot, an immutable
plan store and an incarnation/epoch pair. It is an inspection surface, not an authority boundary: the
framed transport is unauthenticated and unencrypted and must run on a trusted transport.

* Restarting the process produces a new incarnation with a strictly higher epoch. A frame pinned to
  a superseded epoch is fenced. Epoch continuity is reported, and an unreadable incarnation record is
  quarantined rather than dropped.
* A snapshot restored from disk is presented to callers as *not fresh*; planning against it is
  `INDETERMINATE` until the evidence is re-ingested.
* Connections, frame payloads, the plan store, the cancellation table and the worker set are all
  bounded, and a refused frame is answered rather than dropped.
* Cancellation is real: a cancelled search publishes no candidate and the plan store does not gain an
  artifact for it.

## Command line

```
opp version
opp selftest
opp hash <file>
opp gen --out <file> [--seed N] [--nodes N] [--degree N] [--slots N] [--grid fixed50|flex12_5] ...
opp example --out <file>
opp snapshot describe <file> [--json]
opp snapshot validate <file>
opp plan --snapshot <file> (--request <file> | --from node:port --to node:port) [options] [--json]
opp validate-plan --snapshot <file> --plan <file> [--accept-restored] [--revalidate]
opp store list|put|get --root <dir> ...
```

`opp gen` and `opp example` produce SYNTHETIC topologies. They are test, benchmark and demonstration
fixtures: no field in a generated snapshot is a measurement of any real link.

## Building

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cmake --install build --prefix <prefix>
```

Options: `OPP_BUILD_TESTS`, `OPP_BUILD_EXAMPLES`, `OPP_BUILD_BENCHMARKS`, `OPP_BUILD_TOOLS`,
`OPP_WARNINGS_AS_ERRORS` (on by default), `OPP_ENABLE_ASAN`, `OPP_ENABLE_ANALYZE`.

The installed package exports `SummonSoftwareLabs::OpticalPathPlanner` for `find_package(OpticalPathPlanner CONFIG)`.
`consumer/` is an independent project that is not part of this build; it exists to prove the installed
package is usable from a separate CMake project with no access to this source tree.

## Limits

All externally derived quantities are bounded before allocation: nodes, ports, spans, cross-connects,
reach profiles, sources, failure domains per resource, spectrum slots, exclusions, requested
candidates, hops, regenerations, search expansions, labels, witness entries, plan artifact bytes,
store capacity, frame bytes, connections and pending cancellations. Size arithmetic is checked and a
declared size that exceeds its bound is refused rather than allocated.

## Verification

Four suites run under CTest and depend on no external framework, no fixed port and no timeout:

* `core` covers identities, canonical codecs, SHA-256 vectors, spectrum rules, snapshot ingestion and
  its rejection paths, request validation, plan and result sealing, the store's integrity behaviour,
  plan validation against current evidence, and deterministic byte-stable plan identity.
* `oracle` differential-tests the production search against an independent reference solver that
  enumerates every port-simple route and re-derives the constraint rules, the spectrum arithmetic and
  the segment accounting from the raw records. Chains, rings, meshes and flexible-grid fixtures are
  compared across randomized constraint sets, and a state budget turns an accidental blow-up into a
  loud failure instead of a hang.
* `adversarial` exercises malformed input by seeded mutation, bounded-input rejection, cost overflow,
  knowledge frontiers, conflicting evidence, replayed plans after a generation bump, search bounds,
  and cancellation driven by the search's own observation hook rather than by timing.
* `race` covers concurrent planning, snapshot replacement during planning, concurrent store access,
  cancellation from another thread, and the real multi-process service proofs: independent `oppd`
  processes over loopback TCP, forced termination, restart with a higher epoch, fencing of the
  superseded epoch, restored evidence that is never fresh, remote cancellation that publishes
  nothing, and malformed frames that do not take the service down.

`OPP_ENABLE_ASAN=ON` builds the whole runtime and the suites under AddressSanitizer.

## Boundaries

* **No authority.** This runtime computes candidates. It does not activate paths, reserve spectrum,
  own transceiver knowledge, measure link quality or own cable and attachment provenance.
* **Single host.** The multi-process proofs run one service and one client on one host over loopback.
  Multi-host operation, distributed consensus and real fabric hardware are UNSUPPORTED here.
* **No vendor protocols.** No optical hardware control, no vendor SDK integration, no switch or ASIC
  behaviour, no physical telemetry. Every generated fixture is SYNTHETIC.
* **Evidence supply.** How other runtimes publish topology, capability, spectrum, quality and
  failure-domain records is outside this repository. The snapshot reader is the only ingestion path.
* **Modelled semantics only.** `opp` supports explicit exclusions, failure-domain member limits,
  end-to-end quality ceilings, regeneration and conversion policy, ordered candidate enumeration and
  pairwise disjoint candidate selection. A caller asking for semantics outside that surface — spectrum
  continuity across a regeneration, repeated resources — receives UNSUPPORTED rather than a plan
  computed under different rules.
* **No transit waypoints.** A request names one source and one destination port. Ordered waypoint
  routing is not modelled.
* **Integrity is not authentication.** The framed transport is unauthenticated and unencrypted.
* **One request at a time.** The service dispatches one planning request per registered connection; it
  does not replicate, compare or quorum results, and a request that reaches the configured search
  bound is reported as INDETERMINATE rather than retried.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
