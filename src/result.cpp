#include "opp/result.hpp"

#include <algorithm>
#include <string>
#include <vector>

#include "opp/canonical.hpp"
#include "opp/limits.hpp"
#include "opp/sha256.hpp"
#include "opp/version.hpp"

namespace opp {
namespace {

constexpr const char* kResultDigestDomain = "OPP-RESULT-v1";

const struct {
  std::uint32_t bit;
  const char* name;
} kLimitationNames[] = {
    {kLimitationUnknownAdjacency, "unknown_adjacency"},
    {kLimitationUnknownQualityField, "unknown_quality_field"},
    {kLimitationUnknownSpectrum, "unknown_spectrum"},
    {kLimitationConflictingEvidence, "conflicting_evidence"},
    {kLimitationStaleEvidence, "stale_evidence"},
    {kLimitationRestoredEvidence, "restored_evidence"},
    {kLimitationSearchTruncated, "search_truncated"},
    {kLimitationUnresolvedReference, "unresolved_reference"},
    {kLimitationDisjointnessGreedy, "disjointness_greedy"},
    {kLimitationOptimalityNotProven, "optimality_not_proven"},
};

std::string FormatSafe(double value) {
  const Expected<std::string> text = FormatDouble(value);
  return text.ok() ? text.value() : std::string("nan");
}

std::string ResultToTextImpl(const PlanningResult& result) {
  std::string out;
  out.reserve(1024);
  out += "OPP-RESULT 1\n";
  const auto emit = [&out](const LineAssembler& line) {
    out += line.text();
    out += "\n";
  };
  {
    LineAssembler line("outcome");
    line.Add(PlanOutcomeName(result.outcome));
    emit(line);
  }
  {
    LineAssembler line("status");
    line.Add(StatusCodeName(result.status.code));
    line.AddKeyToken("detail", result.status.detail);
    emit(line);
  }
  {
    LineAssembler line("request-digest");
    line.Add(result.request_digest.ToHex());
    emit(line);
  }
  {
    LineAssembler line("snapshot-digest");
    line.Add(result.snapshot_digest.ToHex());
    emit(line);
  }
  {
    LineAssembler line("limitations");
    line.AddU32(result.limitations);
    line.AddKeyToken("names", DescribeLimitations(result.limitations));
    emit(line);
  }
  {
    LineAssembler line("optimality");
    line.Add(result.optimality_proven ? "proven" : "not_proven");
    emit(line);
  }
  {
    LineAssembler line("statistics");
    line.AddKeyU64("labels_created", result.statistics.labels_created);
    line.AddKeyU64("labels_expanded", result.statistics.labels_expanded);
    line.AddKeyU64("labels_dominated", result.statistics.labels_dominated);
    line.AddKeyU64("peak_frontier", result.statistics.peak_frontier);
    line.AddKeyU64("arcs_examined", result.statistics.arcs_examined);
    line.AddKeyU64("states_visited", result.statistics.states_visited);
    line.AddKeyU64("truncated", result.statistics.truncated ? 1u : 0u);
    emit(line);
  }
  for (const Witness& witness : result.witnesses) {
    LineAssembler line("witness");
    line.Add(CutReasonName(witness.reason));
    line.AddKeyToken("res", ResourceKeyToString(witness.resource));
    line.AddKeyToken("detail", witness.detail);
    emit(line);
  }
  for (const CutCount& cut : result.cuts) {
    LineAssembler line("cut");
    line.Add(CutReasonName(cut.reason));
    line.AddU64(cut.count);
    emit(line);
  }
  for (const PlanArtifact& plan : result.candidates) {
    LineAssembler line("candidate");
    line.Add(plan.DigestHex());
    emit(line);
    out += "candidate-plan-begin\n";
    out += plan.CanonicalBytes();
    out += "candidate-plan-end\n";
  }
  {
    LineAssembler line("digest");
    line.Add(result.result_digest.ToHex());
    emit(line);
  }
  return out;
}

}  // namespace

const char* PlanOutcomeName(PlanOutcome outcome) noexcept {
  switch (outcome) {
    case PlanOutcome::Feasible:
      return "FEASIBLE";
    case PlanOutcome::Infeasible:
      return "INFEASIBLE";
    case PlanOutcome::Indeterminate:
      return "INDETERMINATE";
    case PlanOutcome::Unsupported:
      return "UNSUPPORTED";
    case PlanOutcome::Cancelled:
      return "CANCELLED";
    case PlanOutcome::Refused:
      return "REFUSED";
  }
  return "REFUSED";
}

const char* CutReasonName(CutReason reason) noexcept {
  switch (reason) {
    case CutReason::None:
      return "none";
    case CutReason::SourceAbsent:
      return "source_absent";
    case CutReason::DestinationAbsent:
      return "destination_absent";
    case CutReason::SourceAdminDown:
      return "source_admin_down";
    case CutReason::DestinationAdminDown:
      return "destination_admin_down";
    case CutReason::NodeExcluded:
      return "node_excluded";
    case CutReason::PortExcluded:
      return "port_excluded";
    case CutReason::SpanExcluded:
      return "span_excluded";
    case CutReason::FailureDomainExcluded:
      return "failure_domain_excluded";
    case CutReason::FailureDomainMemberLimit:
      return "failure_domain_member_limit";
    case CutReason::SpanAdminDown:
      return "span_admin_down";
    case CutReason::CrossConnectAdminDown:
      return "crossconnect_admin_down";
    case CutReason::NoOutgoingArc:
      return "no_outgoing_arc";
    case CutReason::PortSpectrumEmpty:
      return "port_spectrum_empty";
    case CutReason::SegmentProfileAbsent:
      return "segment_profile_absent";
    case CutReason::SegmentProfileUnknown:
      return "segment_profile_unknown";
    case CutReason::ReachDistanceExceeded:
      return "reach_distance_exceeded";
    case CutReason::ReachSpanCountExceeded:
      return "reach_span_count_exceeded";
    case CutReason::ReachLossExceeded:
      return "reach_loss_exceeded";
    case CutReason::ReachOsnrBelowMinimum:
      return "reach_osnr_below_minimum";
    case CutReason::TotalDistanceExceeded:
      return "total_distance_exceeded";
    case CutReason::TotalSpanCountExceeded:
      return "total_span_count_exceeded";
    case CutReason::TotalLossExceeded:
      return "total_loss_exceeded";
    case CutReason::RegenerationNotAllowed:
      return "regeneration_not_allowed";
    case CutReason::RegenerationLimitExceeded:
      return "regeneration_limit_exceeded";
    case CutReason::ConversionNotAllowed:
      return "conversion_not_allowed";
    case CutReason::HopLimitExceeded:
      return "hop_limit_exceeded";
    case CutReason::CostLimitExceeded:
      return "cost_limit_exceeded";
    case CutReason::LoopPrevented:
      return "loop_prevented";
    case CutReason::Dominated:
      return "dominated";
    case CutReason::UnresolvedReference:
      return "unresolved_reference";
    case CutReason::SearchTruncated:
      return "search_truncated";
    case CutReason::UnknownQualityField:
      return "unknown_quality_field";
    case CutReason::UnknownSpectrum:
      return "unknown_spectrum";
    case CutReason::ConflictingEvidence:
      return "conflicting_evidence";
    case CutReason::PartialCoverage:
      return "partial_coverage";
    case CutReason::TransmitProfileUnknown:
      return "transmit_profile_unknown";
  }
  return "none";
}

std::string DescribeLimitations(std::uint32_t limitations) {
  std::string out;
  for (const auto& entry : kLimitationNames) {
    if ((limitations & entry.bit) == 0) continue;
    if (!out.empty()) out.push_back(',');
    out += entry.name;
  }
  if (out.empty()) out = "none";
  return out;
}

std::string ExplainOutcome(const PlanningResult& result) {
  std::string out;
  out += PlanOutcomeName(result.outcome);
  out += ": ";
  switch (result.outcome) {
    case PlanOutcome::Feasible:
      out += "a proven route satisfies every declared constraint";
      break;
    case PlanOutcome::Infeasible:
      out += "the search exhausted the reachable state space and every label was cut for a proven reason";
      break;
    case PlanOutcome::Indeterminate:
      out += "missing, stale or conflicting evidence prevents proof either way";
      break;
    case PlanOutcome::Unsupported:
      out += "the requested semantics are outside the modelled capability surface";
      break;
    case PlanOutcome::Cancelled:
      out += "the caller cancelled the search before a candidate was produced";
      break;
    case PlanOutcome::Refused:
      out += "the request was rejected before any search started";
      break;
  }
  if (result.status.failed()) {
    out += " [";
    out += StatusCodeName(result.status.code);
    out += "] ";
    out += result.status.detail;
  }
  return out;
}

std::string PlanningResult::ExplainText() const {
  std::string out;
  out += "outcome: ";
  out += PlanOutcomeName(outcome);
  out += "\n";
  if (status.failed()) {
    out += "status: ";
    out += StatusCodeName(status.code);
    out += " ";
    out += status.detail;
    out += "\n";
  }
  out += "explanation: ";
  out += ExplainOutcome(*this);
  out += "\n";
  out += "limitations: ";
  out += DescribeLimitations(limitations);
  out += "\n";
  out += "optimality_proven: ";
  out += optimality_proven ? "true" : "false";
  out += "\n";
  out += "search: labels_created=";
  out += FormatU64(statistics.labels_created);
  out += " labels_expanded=";
  out += FormatU64(statistics.labels_expanded);
  out += " labels_dominated=";
  out += FormatU64(statistics.labels_dominated);
  out += " states_visited=";
  out += FormatU64(statistics.states_visited);
  out += " peak_frontier=";
  out += FormatU64(statistics.peak_frontier);
  out += " truncated=";
  out += statistics.truncated ? "true" : "false";
  out += "\n";
  for (const CutCount& cut : cuts) {
    out += "cut ";
    out += CutReasonName(cut.reason);
    out += " ";
    out += FormatU64(cut.count);
    out += "\n";
  }
  for (const Witness& witness : witnesses) {
    out += "witness ";
    out += CutReasonName(witness.reason);
    out += " ";
    out += ResourceKeyToString(witness.resource);
    if (!witness.detail.empty()) {
      out += " ";
      out += witness.detail;
    }
    out += "\n";
  }
  for (std::size_t i = 0; i < candidates.size(); ++i) {
    const PlanArtifact& plan = candidates[i];
    out += "candidate ";
    out += FormatU64(i);
    out += " digest=";
    out += plan.DigestHex();
    out += " cost=";
    out += FormatU64(plan.total_cost);
    out += " hops=";
    out += FormatU64(plan.hops);
    out += " distance_m=";
    out += FormatU64(plan.total_distance_m);
    out += " regenerations=";
    out += FormatU64(plan.regenerations);
    out += "\n";
    for (const PlanStep& step : plan.steps) {
      out += "  step ";
      out += FormatU32(step.index);
      out += " ";
      out += StepKindName(step.kind);
      out += " ";
      out += ResourceKeyToString(step.resource);
      out += " segment=";
      out += FormatU32(step.segment_index);
      out += " reasons=";
      out += DescribeEligibility(step.reason_bits);
      out += "\n";
    }
    for (const PlanSegment& segment : plan.segments) {
      out += "  segment ";
      out += FormatU32(segment.index);
      out += " profile=";
      out += segment.profile.str();
      out += " channel_runs=";
      out += FormatU32(segment.channel_runs);
      out += " spans=";
      out += FormatU32(segment.span_count);
      out += " distance_m=";
      out += FormatU64(segment.distance_m);
      out += " loss_db=";
      out += FormatSafe(segment.loss_db);
      out += " osnr_db=";
      out += FormatSafe(segment.osnr_db);
      out += segment.ended_by_regeneration ? " ended_by_regeneration" : "";
      out += "\n";
      for (const PlanSpanUse& span : segment.spans) {
        out += "    span ";
        out += span.id.str();
        out += " ";
        out += span.from.CanonicalText();
        out += " -> ";
        out += span.to.CanonicalText();
        out += " slot=";
        out += FormatU16(span.first_slot);
        out += " length_m=";
        out += FormatU64(span.length_m);
        out += " loss_db=";
        out += FormatSafe(span.loss_db);
        out += " osnr_db=";
        out += FormatSafe(span.osnr_db);
        out += "\n";
      }
    }
    for (const PlanReservation& reservation : plan.reservations) {
      out += "  reservation ";
      out += ResourceKeyToString(reservation.resource);
      out += " channel=";
      out += FormatU16(reservation.channel.first_slot);
      out += "+";
      out += FormatU16(reservation.channel.width_slots);
      out += "\n";
    }
    for (const FailureDomainExposure& exposure : plan.failure_domain_exposure) {
      out += "  exposure ";
      out += exposure.id.str();
      out += " members=";
      out += FormatU32(exposure.member_count);
      out += " limit=";
      out += FormatU32(exposure.limit);
      out += "\n";
    }
  }
  return out;
}

std::string PlanningResult::CanonicalBytes() const { return ResultToTextImpl(*this); }

void PlanningResult::Seal() {
  // The digest is computed over the canonical text with a zeroed digest field,
  // so sealing is idempotent and a parsed result can be re-sealed to check it.
  Sha256 hasher;
  hasher.Update(kResultDigestDomain);
  hasher.Update("\n");
  PlanningResult copy = *this;
  copy.result_digest = Digest256{};
  hasher.Update(copy.CanonicalBytes());
  result_digest = hasher.Finalize();
}

Expected<PlanningResult> ParseResultText(std::string_view text) {
  PlanningResult result;
  bool header_seen = false;
  bool digest_seen = false;
  bool in_candidate = false;
  std::string candidate_buffer;
  std::vector<Digest256> expected_digests;

  std::size_t cursor = 0;
  std::size_t line_number = 0;
  while (cursor <= text.size()) {
    if (cursor == text.size()) break;
    const std::size_t newline = text.find('\n', cursor);
    std::string_view line =
        newline == std::string_view::npos ? text.substr(cursor) : text.substr(cursor, newline - cursor);
    cursor = newline == std::string_view::npos ? text.size() : newline + 1;
    ++line_number;
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);

    if (in_candidate) {
      if (line == "candidate-plan-end") {
        auto plan = ParsePlanArtifact(candidate_buffer);
        if (!plan.ok()) {
          return Failure(plan.status().code, "candidate plan: " + plan.status().detail);
        }
        if (!expected_digests.empty() && !(plan.value().digest == expected_digests.back())) {
          return Failure(StatusCode::IntegrityFailure, "candidate plan digest disagrees with its index record");
        }
        result.candidates.push_back(std::move(plan.value()));
        candidate_buffer.clear();
        in_candidate = false;
        continue;
      }
      candidate_buffer += line;
      candidate_buffer.push_back('\n');
      if (candidate_buffer.size() > kMaxPlanArtifactBytes) {
        return Failure(StatusCode::LimitExceeded, "candidate plan exceeds the permitted maximum size");
      }
      continue;
    }

    if (line.empty()) continue;
    const auto tokens = SplitTokens(line);
    if (!tokens.ok()) {
      return Failure(tokens.status().code, "line " + std::to_string(line_number) + ": " + tokens.status().detail);
    }
    const std::vector<std::string>& values = tokens.value();
    const auto fail = [&](const Status& status) -> Expected<PlanningResult> {
      const Status normalised = NormaliseDecodeStatus(status);
      return Failure(normalised.code, "line " + std::to_string(line_number) + ": " + normalised.detail);
    };

    if (!header_seen) {
      if (values.size() != 2 || values[0] != "OPP-RESULT") {
        return Failure(StatusCode::MalformedInput, "result must start with the OPP-RESULT magic line");
      }
      header_seen = true;
      continue;
    }
    if (digest_seen) return Failure(StatusCode::MalformedInput, "result content appears after the digest line");

    const std::string& keyword = values[0];
    if (keyword == "candidate-plan-begin") {
      in_candidate = true;
      candidate_buffer.clear();
      continue;
    }
    if (keyword == "outcome") {
      if (values.size() != 2) return fail(Failure(StatusCode::MalformedInput, "outcome takes one value"));
      static const struct {
        const char* name;
        PlanOutcome outcome;
      } kTable[] = {{"FEASIBLE", PlanOutcome::Feasible},
                    {"INFEASIBLE", PlanOutcome::Infeasible},
                    {"INDETERMINATE", PlanOutcome::Indeterminate},
                    {"UNSUPPORTED", PlanOutcome::Unsupported},
                    {"CANCELLED", PlanOutcome::Cancelled},
                    {"REFUSED", PlanOutcome::Refused}};
      bool matched = false;
      for (const auto& entry : kTable) {
        if (values[1] == entry.name) {
          result.outcome = entry.outcome;
          matched = true;
          break;
        }
      }
      if (!matched) return fail(Failure(StatusCode::MalformedInput, "outcome value is not recognised"));
      continue;
    }
    if (keyword == "status") {
      if (values.size() < 2) return fail(Failure(StatusCode::MalformedInput, "status takes a code"));
      static const StatusCode kCodes[] = {
          StatusCode::Ok,            StatusCode::InvalidArgument, StatusCode::MalformedInput,
          StatusCode::LimitExceeded, StatusCode::DuplicateIdentity, StatusCode::NotFound,
          StatusCode::ConflictingEvidence, StatusCode::Unsupported, StatusCode::Stale,
          StatusCode::Fenced,        StatusCode::Cancelled,       StatusCode::Truncated,
          StatusCode::IntegrityFailure, StatusCode::IoFailure,    StatusCode::Refused,
          StatusCode::Exhausted,     StatusCode::Overflow,        StatusCode::Internal};
      bool matched = false;
      for (StatusCode code : kCodes) {
        if (values[1] == StatusCodeName(code)) {
          result.status.code = code;
          matched = true;
          break;
        }
      }
      if (!matched) return fail(Failure(StatusCode::MalformedInput, "status code is not recognised"));
      const auto detail = FindKeyedField(values, 2, "detail");
      if (detail.ok()) {
        auto decoded = DecodeToken(detail.value());
        if (!decoded.ok()) return fail(decoded.status());
        result.status.detail = decoded.value();
      }
      continue;
    }
    if (keyword == "request-digest" || keyword == "snapshot-digest") {
      if (values.size() != 2) return fail(Failure(StatusCode::MalformedInput, "digest record takes one value"));
      auto parsed = Digest256::FromHex(values[1]);
      if (!parsed.ok()) return fail(parsed.status());
      if (keyword == "request-digest") {
        result.request_digest = parsed.value();
      } else {
        result.snapshot_digest = parsed.value();
      }
      continue;
    }
    if (keyword == "limitations") {
      if (values.size() < 2) return fail(Failure(StatusCode::MalformedInput, "limitations takes a mask"));
      auto parsed = ParseU32(values[1]);
      if (!parsed.ok()) return fail(parsed.status());
      result.limitations = parsed.value();
      continue;
    }
    if (keyword == "optimality") {
      if (values.size() != 2) return fail(Failure(StatusCode::MalformedInput, "optimality takes one value"));
      if (values[1] == "proven") {
        result.optimality_proven = true;
      } else if (values[1] == "not_proven") {
        result.optimality_proven = false;
      } else {
        return fail(Failure(StatusCode::MalformedInput, "optimality value is not recognised"));
      }
      continue;
    }
    if (keyword == "statistics") {
      const auto read = [&](const char* key, std::uint64_t* out) -> Status {
        auto raw = FindKeyedField(values, 1, key);
        if (!raw.ok()) return raw.status();
        auto parsed = ParseU64(raw.value());
        if (!parsed.ok()) return parsed.status();
        *out = parsed.value();
        return OkStatus();
      };
      Status status = read("labels_created", &result.statistics.labels_created);
      if (status.failed()) return fail(status);
      status = read("labels_expanded", &result.statistics.labels_expanded);
      if (status.failed()) return fail(status);
      status = read("labels_dominated", &result.statistics.labels_dominated);
      if (status.failed()) return fail(status);
      status = read("peak_frontier", &result.statistics.peak_frontier);
      if (status.failed()) return fail(status);
      status = read("arcs_examined", &result.statistics.arcs_examined);
      if (status.failed()) return fail(status);
      status = read("states_visited", &result.statistics.states_visited);
      if (status.failed()) return fail(status);
      std::uint64_t truncated = 0;
      status = read("truncated", &truncated);
      if (status.failed()) return fail(status);
      result.statistics.truncated = truncated != 0;
      continue;
    }
    if (keyword == "witness") {
      if (values.size() < 2) return fail(Failure(StatusCode::MalformedInput, "witness takes a reason"));
      Witness witness;
      const auto reason = FindCutReasonByName(values[1]);
      if (!reason.has_value()) {
        return fail(Failure(StatusCode::MalformedInput, "witness reason is not recognised"));
      }
      witness.reason = reason.value();
      const auto resource = FindKeyedField(values, 2, "res");
      if (!resource.ok()) return fail(resource.status());
      auto decoded = DecodeToken(resource.value());
      if (!decoded.ok()) return fail(decoded.status());
      auto parsed_resource = ResourceKeyFromString(decoded.value());
      if (!parsed_resource.ok()) return fail(parsed_resource.status());
      witness.resource = std::move(parsed_resource.value());
      const auto detail = FindKeyedField(values, 2, "detail");
      if (detail.ok()) {
        auto decoded_detail = DecodeToken(detail.value());
        if (!decoded_detail.ok()) return fail(decoded_detail.status());
        witness.detail = decoded_detail.value();
      }
      result.witnesses.push_back(std::move(witness));
      continue;
    }
    if (keyword == "cut") {
      if (values.size() != 3) return fail(Failure(StatusCode::MalformedInput, "cut takes a reason and a count"));
      const auto reason = FindCutReasonByName(values[1]);
      if (!reason.has_value()) {
        return fail(Failure(StatusCode::MalformedInput, "cut reason is not recognised"));
      }
      auto count = ParseU64(values[2]);
      if (!count.ok()) return fail(count.status());
      result.cuts.push_back(CutCount{reason.value(), count.value()});
      continue;
    }
    if (keyword == "candidate") {
      if (values.size() != 2) return fail(Failure(StatusCode::MalformedInput, "candidate takes a digest"));
      auto parsed = Digest256::FromHex(values[1]);
      if (!parsed.ok()) return fail(parsed.status());
      expected_digests.push_back(parsed.value());
      continue;
    }
    if (keyword == "digest") {
      if (values.size() != 2) return fail(Failure(StatusCode::MalformedInput, "digest takes one value"));
      auto parsed = Digest256::FromHex(values[1]);
      if (!parsed.ok()) return fail(parsed.status());
      result.result_digest = parsed.value();
      digest_seen = true;
      continue;
    }
    return fail(Failure(StatusCode::MalformedInput, "unknown result record '" + keyword + "'"));
  }

  if (!header_seen) return Failure(StatusCode::MalformedInput, "result is empty");
  if (!digest_seen) return Failure(StatusCode::MalformedInput, "result is missing its digest line");
  if (in_candidate) return Failure(StatusCode::MalformedInput, "result ends inside a candidate plan");

  const Digest256 declared = result.result_digest;
  PlanningResult copy = result;
  copy.Seal();
  if (!(copy.result_digest == declared)) {
    return Failure(StatusCode::IntegrityFailure, "result digest does not match its content");
  }
  return result;
}

std::optional<CutReason> FindCutReasonByName(std::string_view name) {
  for (std::uint32_t i = 0; i <= static_cast<std::uint32_t>(CutReason::TransmitProfileUnknown); ++i) {
    const auto reason = static_cast<CutReason>(i);
    if (name == CutReasonName(reason)) return reason;
  }
  return std::nullopt;
}

}  // namespace opp
