// Guards for the planner's completed-work rate.
//
// These measurements are of SYNTHETIC topologies generated in this process. They
// say nothing about optical hardware, real fibre, real link quality or any
// vendor device. What they do measure is completed useful work: a run counts a
// plan only when the planner returned a sealed artifact, so submission or
// enqueue cost is not reported as throughput.
//
// The guards are intentionally loose. They exist to catch a collapse in
// behaviour (an accidental quadratic, a lost pruning rule, a pathological
// allocation pattern), not to pin a machine-specific number.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include "opp/opp.hpp"

namespace {

using namespace opp;

struct Case {
  const char* label;
  std::uint32_t nodes;
  std::uint32_t degree;
  std::uint16_t slots;
  std::uint32_t requests;
};

struct Measurement {
  std::uint64_t completed = 0;
  std::uint64_t feasible = 0;
  std::uint64_t infeasible = 0;
  std::uint64_t indeterminate = 0;
  std::uint64_t unsupported = 0;
  double total_ms = 0.0;
  double slowest_ms = 0.0;
  std::uint64_t labels = 0;
};

Measurement RunCase(const Case& bench_case) {
  SyntheticOptions options;
  options.seed = 20260101 + bench_case.nodes;
  options.node_count = bench_case.nodes;
  options.degree = bench_case.degree;
  options.slot_count = bench_case.slots;
  options.generation = 1;

  const auto snapshot = GenerateSyntheticTopology(options);
  if (!snapshot.ok()) {
    std::fprintf(stderr, "generation failed: %s\n", snapshot.status().detail.c_str());
    return Measurement{};
  }

  Measurement measurement;
  const Planner planner;
  const std::uint32_t clients = 2;
  std::uint64_t accepted = 0;

  const auto started = std::chrono::steady_clock::now();
  for (std::uint32_t index = 0; index < bench_case.requests; ++index) {
    const std::uint32_t from = (index * 7u) % bench_case.nodes;
    const std::uint32_t to = (index * 13u + 5u) % bench_case.nodes;
    if (from == to) continue;

    PlanningRequest request;
    request.id = RequestId::Trusted("bench");
    request.source = PortKey{NodeId::Trusted("n" + std::to_string(from)),
                             PortId::Trusted("c" + std::to_string(index % clients))};
    request.destination = PortKey{NodeId::Trusted("n" + std::to_string(to)),
                                  PortId::Trusted("c" + std::to_string((index + 1) % clients))};
    request.max_candidates = 1;

    const auto request_started = std::chrono::steady_clock::now();
    const PlanningResult result = planner.Plan(snapshot.value(), request);
    const auto request_finished = std::chrono::steady_clock::now();
    const double elapsed_ms =
        std::chrono::duration<double, std::milli>(request_finished - request_started).count();
    measurement.slowest_ms = std::max(measurement.slowest_ms, elapsed_ms);
    measurement.labels += result.statistics.labels_created;

    switch (result.outcome) {
      case PlanOutcome::Feasible:
        // Only a sealed artifact counts as completed work.
        if (result.candidates.size() == 1 && result.candidates.front().VerifySeal().ok()) {
          measurement.completed += 1;
          measurement.feasible += 1;
          accepted += 1;
        }
        break;
      case PlanOutcome::Infeasible:
        measurement.infeasible += 1;
        accepted += 1;
        break;
      case PlanOutcome::Indeterminate:
        measurement.indeterminate += 1;
        accepted += 1;
        break;
      case PlanOutcome::Unsupported:
        measurement.unsupported += 1;
        accepted += 1;
        break;
      default:
        break;
    }
  }
  const auto finished = std::chrono::steady_clock::now();
  measurement.total_ms = std::chrono::duration<double, std::milli>(finished - started).count();

  std::printf("%-22s nodes=%4u degree=%u slots=%3u arcs=%6llu requests=%5u answered=%5llu feasible=%5llu "
              "infeasible=%5llu indeterminate=%4llu total=%9.2f ms mean=%8.3f ms slowest=%8.3f ms "
              "plans_per_second=%9.1f labels=%llu\n",
              bench_case.label, bench_case.nodes, bench_case.degree, bench_case.slots,
              static_cast<unsigned long long>(snapshot.value().ArcCount()), bench_case.requests,
              static_cast<unsigned long long>(accepted), static_cast<unsigned long long>(measurement.feasible),
              static_cast<unsigned long long>(measurement.infeasible),
              static_cast<unsigned long long>(measurement.indeterminate), measurement.total_ms,
              accepted == 0 ? 0.0 : measurement.total_ms / static_cast<double>(accepted), measurement.slowest_ms,
              measurement.total_ms <= 0.0 ? 0.0 : static_cast<double>(accepted) * 1000.0 / measurement.total_ms,
              static_cast<unsigned long long>(measurement.labels));
  return measurement;
}

}  // namespace

int main() {
  std::printf("Optical Path Planner %s benchmark\n", opp::VersionString());
  std::printf("evidence: SYNTHETIC topologies generated in this process; no hardware measurement is implied\n\n");

  const Case cases[] = {
      {"small mesh", 12, 3, 16, 40},
      {"medium mesh", 40, 3, 24, 40},
      {"wide mesh", 80, 4, 32, 20},
      {"large mesh", 160, 4, 32, 10},
  };

  int failures = 0;
  for (const Case& bench_case : cases) {
    const Measurement measurement = RunCase(bench_case);
    if (measurement.completed == 0 && measurement.infeasible == 0 && measurement.indeterminate == 0) {
      std::fprintf(stderr, "case %s produced no answered request\n", bench_case.label);
      failures += 1;
    }
    // Guard: every answered request must have produced a verdict, and the mean
    // must stay under a generous ceiling for these synthetic sizes.
    const double mean_ms = measurement.completed + measurement.infeasible + measurement.indeterminate == 0
                               ? 0.0
                               : measurement.total_ms /
                                     static_cast<double>(measurement.completed + measurement.infeasible +
                                                         measurement.indeterminate);
    if (mean_ms > 20000.0) {
      std::fprintf(stderr, "case %s mean latency guard exceeded: %.3f ms\n", bench_case.label, mean_ms);
      failures += 1;
    }
  }

  std::printf("\nresult: %s\n", failures == 0 ? "guards satisfied" : "guards failed");
  return failures == 0 ? 0 : 1;
}
