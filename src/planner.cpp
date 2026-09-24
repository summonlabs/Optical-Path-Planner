#include "opp/planner.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "opp/canonical.hpp"
#include "search.hpp"

namespace opp {
namespace {

constexpr std::size_t kPlanBuildBudget = 64;

void NoteLimitation(PlanningResult* result, std::uint32_t bit) { result->limitations |= bit; }

// Merges one search pass into the aggregate result so that a plan computed over
// several passes still reports the whole cost of finding it.
void MergeSearch(PlanningResult* result, const detail::SearchOutcome& search) {
  result->statistics.labels_created += search.statistics.labels_created;
  result->statistics.labels_expanded += search.statistics.labels_expanded;
  result->statistics.labels_dominated += search.statistics.labels_dominated;
  result->statistics.arcs_examined += search.statistics.arcs_examined;
  result->statistics.peak_frontier = std::max(result->statistics.peak_frontier, search.statistics.peak_frontier);
  result->statistics.states_visited = std::max(result->statistics.states_visited, search.statistics.states_visited);
  result->statistics.truncated = result->statistics.truncated || search.statistics.truncated;
  result->limitations |= search.limitations;
  for (const Witness& witness : search.witnesses) result->witnesses.push_back(witness);
  for (const CutCount& cut : search.cuts) {
    const auto existing = std::find_if(result->cuts.begin(), result->cuts.end(),
                                       [&cut](const CutCount& entry) { return entry.reason == cut.reason; });
    if (existing == result->cuts.end()) {
      result->cuts.push_back(cut);
    } else {
      existing->count += cut.count;
    }
  }
}

// Adds the resources of an accepted plan to the exclusion set of the next pass,
// which is what makes the returned candidates pairwise disjoint by construction
// rather than by post-filtering.
void ExtendExclusions(const PlanArtifact& plan, Disjointness kind, std::vector<NodeId>* nodes,
                      std::vector<SpanId>* spans, std::vector<FailureDomainId>* domains) {
  switch (kind) {
    case Disjointness::Node:
      for (const PlanStep& step : plan.steps) {
        if (step.resource.kind() == ResourceKind::Node) {
          const auto id = NodeId::Parse(step.resource.text());
          if (id.ok()) nodes->push_back(id.value());
          continue;
        }
        if (step.resource.kind() == ResourceKind::Port) {
          const std::string& text = step.resource.text();
          const std::size_t colon = text.find(':');
          if (colon == std::string::npos) continue;
          const auto id = NodeId::Parse(std::string_view(text).substr(0, colon));
          if (id.ok()) nodes->push_back(id.value());
        }
      }
      break;
    case Disjointness::Span:
      for (const PlanStep& step : plan.steps) {
        if (step.resource.kind() != ResourceKind::Span) continue;
        const auto id = SpanId::Parse(step.resource.text());
        if (id.ok()) spans->push_back(id.value());
      }
      break;
    case Disjointness::FailureDomain:
      for (const FailureDomainExposure& exposure : plan.failure_domain_exposure) {
        domains->push_back(exposure.id);
      }
      break;
    case Disjointness::None:
      break;
  }
}

template <class T>
void SortUnique(std::vector<T>* values) {
  std::sort(values->begin(), values->end());
  values->erase(std::unique(values->begin(), values->end()), values->end());
}

void FinaliseResult(PlanningResult* result) {
  std::sort(result->witnesses.begin(), result->witnesses.end(), [](const Witness& lhs, const Witness& rhs) {
    if (lhs.reason != rhs.reason) return lhs.reason < rhs.reason;
    if (!(lhs.resource == rhs.resource)) return lhs.resource < rhs.resource;
    return lhs.detail < rhs.detail;
  });
  result->witnesses.erase(std::unique(result->witnesses.begin(), result->witnesses.end()), result->witnesses.end());
  if (result->witnesses.size() > kMaxWitnessEntries) result->witnesses.resize(kMaxWitnessEntries);
  std::sort(result->cuts.begin(), result->cuts.end(), [](const CutCount& lhs, const CutCount& rhs) {
    return lhs.reason < rhs.reason;
  });
  result->Seal();
}

}  // namespace

bool IsOpAllowed(const ConstraintSet& constraints, CrossConnectOp op) noexcept {
  switch (op) {
    case CrossConnectOp::Express:
      return true;
    case CrossConnectOp::Convert:
      return constraints.allow_wavelength_conversion;
    case CrossConnectOp::Regenerate:
      return constraints.allow_regeneration;
  }
  return false;
}

PlanningResult Planner::Plan(const TopologySnapshot& snapshot, const PlanningRequest& request,
                             const CancelToken& cancel, const SearchObserver& observer) const {
  PlanningResult result;
  result.request_digest = ComputeRequestDigest(request);
  result.snapshot_digest = snapshot.digest();

  // ---- 1. structural validation ------------------------------------------
  const Status request_status = request.Validate();
  if (request_status.failed()) {
    result.outcome = request_status.code == StatusCode::Unsupported ? PlanOutcome::Unsupported : PlanOutcome::Refused;
    result.status = request_status;
    FinaliseResult(&result);
    return result;
  }

  // ---- 2. evidence freshness ---------------------------------------------
  if (snapshot.freshness() != EvidenceFreshness::Fresh && !request.accept_restored_evidence) {
    result.outcome = PlanOutcome::Indeterminate;
    result.status = Failure(StatusCode::Stale,
                            "the snapshot was restored from persistence and the caller did not accept restored "
                            "evidence");
    NoteLimitation(&result, kLimitationRestoredEvidence | kLimitationStaleEvidence);
    Witness witness;
    witness.reason = CutReason::UnresolvedReference;
    witness.resource = ResourceKey::ForSource(SourceId::Trusted("snapshot"));
    witness.detail = "restored from incarnation " + snapshot.restored_from_incarnation().ToHex();
    result.witnesses.push_back(std::move(witness));
    FinaliseResult(&result);
    return result;
  }

  if (request.required_snapshot_generation.has_value() &&
      snapshot.generation() < request.required_snapshot_generation.value()) {
    result.outcome = PlanOutcome::Indeterminate;
    result.status = Failure(StatusCode::Stale, "snapshot generation " + FormatU64(snapshot.generation()) +
                                                   " is older than the requested minimum " +
                                                   FormatU64(request.required_snapshot_generation.value()));
    NoteLimitation(&result, kLimitationStaleEvidence);
    FinaliseResult(&result);
    return result;
  }

  if (request.expected_snapshot_digest.has_value() &&
      !(request.expected_snapshot_digest.value() == snapshot.digest())) {
    result.outcome = PlanOutcome::Indeterminate;
    result.status = Failure(StatusCode::Stale, "snapshot digest does not match the digest the request pinned");
    NoteLimitation(&result, kLimitationStaleEvidence);
    FinaliseResult(&result);
    return result;
  }

  for (const auto& entry : request.required_source_generations) {
    if (!snapshot.HasSource(entry.first)) {
      result.outcome = PlanOutcome::Indeterminate;
      result.status = Failure(StatusCode::Stale,
                              "source '" + entry.first.str() +
                                  "' is required by the request but is absent from the snapshot");
      NoteLimitation(&result, kLimitationStaleEvidence);
      Witness witness;
      witness.reason = CutReason::UnresolvedReference;
      witness.resource = ResourceKey::ForSource(entry.first);
      witness.detail = "required evidence source is absent";
      result.witnesses.push_back(std::move(witness));
      FinaliseResult(&result);
      return result;
    }
    const Generation current = snapshot.SourceGeneration(entry.first);
    if (current < entry.second) {
      result.outcome = PlanOutcome::Indeterminate;
      result.status = Failure(StatusCode::Stale, "source '" + entry.first.str() + "' publishes generation " +
                                                     FormatU64(current) + " but the request requires at least " +
                                                     FormatU64(entry.second));
      NoteLimitation(&result, kLimitationStaleEvidence);
      FinaliseResult(&result);
      return result;
    }
  }

  // ---- 3. modelled capability surface ------------------------------------
  const SpectrumModel& spectrum = snapshot.spectrum();
  if (spectrum.grid == GridKind::Fixed50GHz && request.channel_width_slots != 1) {
    result.outcome = PlanOutcome::Unsupported;
    result.status = Failure(StatusCode::Unsupported,
                            "a fixed 50 GHz grid carries single-slot channels; multi-slot widths are only modelled "
                            "on the flexible grid");
    FinaliseResult(&result);
    return result;
  }

  // ---- 4. endpoints -------------------------------------------------------
  const bool source_present = snapshot.FindPort(request.source) != nullptr;
  const bool destination_present = snapshot.FindPort(request.destination) != nullptr;
  if (!source_present || !destination_present) {
    const CutReason reason = source_present ? CutReason::DestinationAbsent : CutReason::SourceAbsent;
    result.cuts.push_back(CutCount{reason, 1});
    if (snapshot.coverage_complete()) {
      result.outcome = PlanOutcome::Infeasible;
      result.status = OkStatus();
    } else {
      result.outcome = PlanOutcome::Indeterminate;
      result.status = Failure(StatusCode::NotFound,
                              "an endpoint has no record and the snapshot does not claim complete coverage");
      NoteLimitation(&result, kLimitationUnknownAdjacency);
      Witness witness;
      witness.reason = reason;
      witness.resource = ResourceKey::ForPort(source_present ? request.destination : request.source);
      witness.detail = "no record for this port";
      result.witnesses.push_back(std::move(witness));
    }
    FinaliseResult(&result);
    return result;
  }

  // ---- 5. search ----------------------------------------------------------
  // With disjointness the planner re-plans once per requested candidate, adding
  // the resources of every accepted candidate to the exclusion set. Each pass is
  // an ordinary exact search over the tightened constraints, so the candidates
  // are pairwise disjoint by construction and each one is optimal given the
  // resources the earlier candidates took.
  const bool iterative = request.disjointness != Disjointness::None && request.max_candidates > 1;

  std::vector<PlanArtifact> accepted;
  std::vector<NodeId> excluded_nodes;
  std::vector<SpanId> excluded_spans;
  std::vector<FailureDomainId> excluded_domains;
  bool first_pass_proved_optimum = false;
  bool stopped_on_knowledge_gap = false;
  bool stopped_on_truncation = false;
  Status stopping_status = OkStatus();

  const std::uint32_t passes = iterative ? request.max_candidates : 1u;
  for (std::uint32_t pass = 0; pass < passes; ++pass) {
    PlanningRequest working = request;
    if (iterative) {
      working.max_candidates = 1;
      working.disjointness = Disjointness::None;
      SortUnique(&excluded_nodes);
      SortUnique(&excluded_spans);
      SortUnique(&excluded_domains);
      for (const NodeId& id : excluded_nodes) working.constraints.excluded_nodes.push_back(id);
      for (const SpanId& id : excluded_spans) working.constraints.excluded_spans.push_back(id);
      for (const FailureDomainId& id : excluded_domains) {
        working.constraints.excluded_failure_domains.push_back(id);
      }
      const Status valid = working.Validate();
      if (valid.failed()) {
        stopping_status = valid;
        break;
      }
    }

    detail::SearchOutcome search = detail::RunSearch(snapshot, working, options_, cancel, observer);
    MergeSearch(&result, search);

    if (search.status.failed()) {
      result.outcome = search.status.code == StatusCode::Cancelled ? PlanOutcome::Cancelled : PlanOutcome::Refused;
      result.status = search.status;
      FinaliseResult(&result);
      return result;
    }

    if (pass == 0) first_pass_proved_optimum = search.proved_optimum;

    const std::size_t build_budget =
        iterative ? std::size_t{1}
                  : (request.disjointness == Disjointness::None
                         ? static_cast<std::size_t>(request.max_candidates)
                         : std::min<std::size_t>(kPlanBuildBudget,
                                                 static_cast<std::size_t>(request.max_candidates) * 8u));

    std::vector<PlanArtifact> built;
    std::set<std::string> seen_digests;
    bool has_unproven_path = false;
    for (const detail::RawPath& path : search.paths) {
      if (!path.proven) {
        has_unproven_path = true;
        continue;
      }
      if (built.size() >= build_budget) break;
      const std::vector<detail::ArcRef> stripped = detail::StripCycles(snapshot, request.source, path.arcs);
      Digest256 digest{};
      Expected<PlanArtifact> plan = detail::BuildPlan(snapshot, request, result.request_digest, stripped, &digest);
      if (!plan.ok()) {
        result.outcome = PlanOutcome::Refused;
        result.status = plan.status();
        FinaliseResult(&result);
        return result;
      }
      if (!seen_digests.insert(digest.ToHex()).second) continue;
      built.push_back(std::move(plan.value()));
    }
    std::sort(built.begin(), built.end(), PlanLess);

    if (built.empty()) {
      if (has_unproven_path) {
        stopped_on_knowledge_gap = true;
        stopping_status = Failure(StatusCode::Stale,
                                  "a route exists only under unpublished evidence, so neither feasibility nor "
                                  "infeasibility can be proven");
      } else if (search.statistics.truncated || !search.exhausted) {
        stopped_on_truncation = true;
        stopping_status = Failure(StatusCode::Truncated,
                                  "the search reached its configured bound before exhausting the reachable state "
                                  "space");
      } else if (!snapshot.coverage_complete()) {
        stopped_on_knowledge_gap = true;
        stopping_status = Failure(StatusCode::Stale,
                                  "the snapshot does not claim complete coverage, so absence of a route cannot be "
                                  "proven");
        NoteLimitation(&result, kLimitationUnknownAdjacency | kLimitationUnresolvedReference);
      }
      break;
    }

    if (!iterative) {
      for (PlanArtifact& plan : built) {
        if (accepted.size() >= request.max_candidates) break;
        accepted.push_back(std::move(plan));
      }
      break;
    }

    ExtendExclusions(built.front(), request.disjointness, &excluded_nodes, &excluded_spans, &excluded_domains);
    accepted.push_back(std::move(built.front()));
  }

  result.candidates = std::move(accepted);

  // ---- 6. outcome classification -----------------------------------------
  if (!result.candidates.empty()) {
    result.outcome = PlanOutcome::Feasible;
    result.status = OkStatus();
    result.optimality_proven = first_pass_proved_optimum && snapshot.coverage_complete();
    if (iterative && result.candidates.size() < request.max_candidates && !stopped_on_knowledge_gap &&
        !stopped_on_truncation) {
      NoteLimitation(&result, kLimitationDisjointnessGreedy);
    }
    if (!result.optimality_proven) NoteLimitation(&result, kLimitationOptimalityNotProven);
    FinaliseResult(&result);
    return result;
  }

  if (stopped_on_knowledge_gap) {
    result.outcome = PlanOutcome::Indeterminate;
    result.status = stopping_status;
    FinaliseResult(&result);
    return result;
  }
  if (stopped_on_truncation) {
    result.outcome = PlanOutcome::Indeterminate;
    result.status = stopping_status;
    NoteLimitation(&result, kLimitationSearchTruncated);
    FinaliseResult(&result);
    return result;
  }

  result.outcome = PlanOutcome::Infeasible;
  result.status = OkStatus();
  result.optimality_proven = false;
  FinaliseResult(&result);
  return result;
}

}  // namespace opp
