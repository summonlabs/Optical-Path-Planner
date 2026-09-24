# Contributing

Contributions to Optical Path Planner are accepted under the Apache License 2.0. By submitting a
change you agree that your contribution is licensed under the same terms as the project. There is no
Contributor License Agreement to sign and no copyright assignment to make: you keep the copyright to
your work and license it to everyone under Apache 2.0.

## Ground rules

* Every change must build warning-clean. First-party targets compile with `/W4 /WX /permissive-` on
  MSVC and `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror` elsewhere; warnings are errors.
* Every change must leave the full test suite green in both Debug and Release:

  ```
  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
  cmake --build build --config Release
  ctest --test-dir build -C Release --output-on-failure
  ```

* Do not add wall-clock timeouts, sleeps, retry-until-green loops or fixed ports to any test. A
  hanging test is a defect in the runtime, not something to work around. Cancellation and
  concurrency tests must rendezvous on a logical condition — a flag the search itself sets, a service
  statistic, a signal — not on elapsed time.
* Keep the outcome vocabulary honest. Never collapse `UNKNOWN`, `UNSUPPORTED`, `STALE`,
  `CONFLICTING`, `INCOMPLETE`, `REFUSED` or `INVALID` into success or into a false `INFEASIBLE`.
* New externally derived quantities need a bound in `include/opp/limits.hpp`, a check before
  allocation, and a test that exercises the refusal.
* New wire, store or file formats need an explicit revision constant, a rejection path for unknown
  revisions, and a round-trip test.

## What belongs here, and what does not

This repository computes candidate routes from explicit evidence. It must not grow authority it does
not have: no path activation, no wavelength reservation, no transceiver mutation, no hardware
programming, and no ownership of the topology, capability, spectrum, quality or attachment evidence it
consumes. Changes that require a new kind of evidence should extend the snapshot format and the
documented semantics rather than reach into another runtime.

## Documentation

The README describes only implemented behaviour. If a change alters an outcome, a bound, a format
revision or a boundary, update the README in the same change. Do not add roadmap or aspirational
claims.

## Commits

Write plain, neutral commit messages that describe the change. Do not add co-author trailers, tool
attribution or generated-by lines.
