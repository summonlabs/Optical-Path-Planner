#include "opp/plan.hpp"

#include <algorithm>
#include <string>
#include <vector>

#include "opp/canonical.hpp"
#include "opp/sha256.hpp"
#include "opp/version.hpp"

namespace opp {
namespace {

constexpr const char* kPlanDigestDomain = "OPP-PLAN-v1";

const struct {
  std::uint32_t bit;
  const char* name;
} kReasonNames[] = {
    {kReasonAdminUp, "admin_up"},
    {kReasonNotExcluded, "not_excluded"},
    {kReasonPortAdmitted, "port_admitted"},
    {kReasonSpectrumAvailable, "spectrum_available"},
    {kReasonWithinReachDistance, "within_reach_distance"},
    {kReasonWithinReachSpans, "within_reach_spans"},
    {kReasonWithinReachLoss, "within_reach_loss"},
    {kReasonWithinReachOsnr, "within_reach_osnr"},
    {kReasonRegenerationBoundary, "regeneration_boundary"},
    {kReasonWavelengthConversion, "wavelength_conversion"},
    {kReasonFailureDomainWithinLimit, "failure_domain_within_limit"},
    {kReasonSourceEvidencePresent, "source_evidence_present"},
    {kReasonSegmentStart, "segment_start"},
    {kReasonTransmitProfileKnown, "transmit_profile_known"},
};

std::string PlanToText(const PlanArtifact& plan, bool include_digest) {
  std::string out;
  out.reserve(1024);
  out += "OPP-PLAN ";
  out += FormatU32(plan.format_version);
  out += "\n";
  const auto emit = [&out](const LineAssembler& line) {
    out += line.text();
    out += "\n";
  };
  {
    LineAssembler line("rule");
    line.AddU32(plan.rule_version);
    emit(line);
  }
  {
    LineAssembler line("request");
    line.Add(plan.request_id.str());
    line.Add(plan.request_digest.ToHex());
    emit(line);
  }
  {
    LineAssembler line("snapshot");
    line.Add(plan.snapshot_id.str());
    line.AddU64(plan.snapshot_generation);
    line.Add(plan.snapshot_digest.ToHex());
    emit(line);
  }
  for (const SourceBinding& binding : plan.bound_sources) {
    LineAssembler line("binding");
    line.Add(binding.source.str());
    line.AddKeyU64("gen", binding.generation);
    line.AddKeyToken("contrib", binding.snapshot_contribution.ToHex());
    emit(line);
  }
  {
    LineAssembler line("endpoints");
    line.AddKeyToken("snode", plan.source.node.str());
    line.AddKeyToken("sport", plan.source.port.str());
    line.AddKeyToken("dnode", plan.destination.node.str());
    line.AddKeyToken("dport", plan.destination.port.str());
    emit(line);
  }
  {
    LineAssembler line("channel");
    line.AddKeyU64("width", plan.channel_width_slots);
    emit(line);
  }
  {
    LineAssembler line("totals");
    line.AddKeyU64("cost", plan.total_cost);
    line.AddKeyU64("distance", plan.total_distance_m);
    line.AddKeyDouble("loss", plan.total_loss_db);
    line.AddKeyU64("hops", plan.hops);
    line.AddKeyU64("regen", plan.regenerations);
    emit(line);
  }
  for (const PlanStep& step : plan.steps) {
    LineAssembler line("step");
    line.AddU32(step.index);
    line.AddKeyToken("kind", StepKindName(step.kind));
    line.AddKeyU64("seg", step.segment_index);
    line.AddKeyU64("reason", step.reason_bits);
    line.AddKeyU64("cost", step.cost);
    line.AddKeyToken("res", ResourceKeyToString(step.resource));
    emit(line);
  }
  for (const PlanSegment& segment : plan.segments) {
    LineAssembler line("segment");
    line.AddU32(segment.index);
    line.AddKeyToken("profile", segment.profile.str());
    line.AddKeyU64("runs", segment.channel_runs);
    line.AddKeyU64("distance", segment.distance_m);
    line.AddKeyDouble("loss", segment.loss_db);
    line.AddKeyDouble("osnr", segment.osnr_db);
    line.AddKeyU64("spans", segment.span_count);
    line.AddKeyToken("end", segment.ended_by_regeneration ? "regeneration" : "transparent");
    if (segment.ended_by_regeneration) {
      line.AddKeyToken("xc", ResourceKeyToString(segment.regeneration_resource));
    }
    emit(line);
  }
  for (const PlanSegment& segment : plan.segments) {
    for (const PlanSpanUse& span : segment.spans) {
      LineAssembler line("segspan");
      line.AddU32(segment.index);
      line.AddKeyToken("id", span.id.str());
      line.AddKeyToken("from", span.from.CanonicalText());
      line.AddKeyToken("to", span.to.CanonicalText());
      line.AddKeyU64("rev", span.reversed ? 1u : 0u);
      line.AddKeyU64("len", span.length_m);
      line.AddKeyDouble("loss", span.loss_db);
      line.AddKeyDouble("osnr", span.osnr_db);
      line.AddKeyU64("cost", span.cost);
      line.AddKeyU64("slot", span.first_slot);
      if (!span.failure_domains.empty()) {
        std::string joined;
        for (std::size_t i = 0; i < span.failure_domains.size(); ++i) {
          if (i != 0) joined.push_back(',');
          joined += span.failure_domains[i].str();
        }
        line.AddKeyRaw("domains", joined);
      }
      emit(line);
    }
  }
  for (const PlanReservation& reservation : plan.reservations) {
    LineAssembler line("reservation");
    line.AddKeyToken("res", ResourceKeyToString(reservation.resource));
    line.AddKeyU64("first", reservation.channel.first_slot);
    line.AddKeyU64("width", reservation.channel.width_slots);
    line.AddKeyU64("seg", reservation.segment_index);
    emit(line);
  }
  for (const PlanAssumption& assumption : plan.capability_assumptions) {
    LineAssembler line("capability");
    line.AddKeyToken("res", ResourceKeyToString(assumption.resource));
    line.AddKeyToken("field", assumption.field);
    line.AddKeyToken("value", assumption.value);
    emit(line);
  }
  for (const PlanAssumption& assumption : plan.quality_assumptions) {
    LineAssembler line("quality");
    line.AddKeyToken("res", ResourceKeyToString(assumption.resource));
    line.AddKeyToken("field", assumption.field);
    line.AddKeyToken("value", assumption.value);
    emit(line);
  }
  for (const FailureDomainExposure& exposure : plan.failure_domain_exposure) {
    LineAssembler line("exposure");
    line.AddKeyToken("domain", exposure.id.str());
    line.AddKeyU64("count", exposure.member_count);
    line.AddKeyU64("limit", exposure.limit);
    emit(line);
  }
  if (include_digest) {
    LineAssembler line("digest");
    line.Add(plan.digest.ToHex());
    emit(line);
  }
  return out;
}

Expected<std::string> RequiredKeyToken(const std::vector<std::string>& tokens, std::size_t first, const char* key) {
  auto raw = FindKeyedField(tokens, first, key);
  if (!raw.ok()) return raw.status();
  return DecodeToken(raw.value());
}

Expected<std::string> RequiredRawField(const std::vector<std::string>& tokens, std::size_t first, const char* key) {
  auto raw = FindKeyedField(tokens, first, key);
  if (raw.ok()) return raw;
  if (raw.status().code == StatusCode::NotFound) {
    // A record that does not carry a field the grammar requires is malformed,
    // whether it was truncated or never well formed.
    return Failure(StatusCode::MalformedInput, std::string("record is missing the '") + key + "' field");
  }
  return raw.status();
}

Expected<std::vector<FailureDomainId>> ParseDomainList(std::string_view text) {
  std::vector<FailureDomainId> domains;
  if (text.empty()) return domains;
  std::size_t start = 0;
  while (true) {
    const std::size_t comma = text.find(',', start);
    const std::string_view piece =
        comma == std::string_view::npos ? text.substr(start) : text.substr(start, comma - start);
    auto id = FailureDomainId::Parse(piece);
    if (!id.ok()) return id.status();
    domains.push_back(std::move(id.value()));
    if (comma == std::string_view::npos) break;
    start = comma + 1;
  }
  return domains;
}

}  // namespace

const char* StepKindName(StepKind kind) noexcept {
  switch (kind) {
    case StepKind::Node:
      return "node";
    case StepKind::Port:
      return "port";
    case StepKind::Span:
      return "span";
    case StepKind::CrossConnect:
      return "crossconnect";
  }
  return "node";
}

std::string DescribeEligibility(std::uint32_t reason_bits) {
  std::string out;
  for (const auto& entry : kReasonNames) {
    if ((reason_bits & entry.bit) == 0) continue;
    if (!out.empty()) out.push_back(',');
    out += entry.name;
  }
  if (out.empty()) out = "none";
  return out;
}

std::string PlanArtifact::DigestPayload() const { return PlanToText(*this, false); }

std::string PlanArtifact::CanonicalBytes() const { return PlanToText(*this, true); }

Digest256 ComputePlanDigest(const PlanArtifact& plan) {
  Sha256 hasher;
  hasher.Update(kPlanDigestDomain);
  hasher.Update("\n");
  hasher.Update(plan.DigestPayload());
  return hasher.Finalize();
}

void PlanArtifact::Seal() { digest = ComputePlanDigest(*this); }

Status PlanArtifact::VerifySeal() const {
  const Digest256 recomputed = ComputePlanDigest(*this);
  if (!(recomputed == digest)) {
    return Failure(StatusCode::IntegrityFailure, "plan digest does not match its content");
  }
  return OkStatus();
}

std::string PlanArtifact::DigestHex() const { return digest.ToHex(); }

std::string PlanArtifact::ResourceSequenceKey() const {
  std::string key;
  for (const PlanStep& step : steps) {
    key += ResourceKindName(step.resource.kind());
    key.push_back('|');
    key += step.resource.text();
    key.push_back('>');
  }
  return key;
}

bool PlanLess(const PlanArtifact& lhs, const PlanArtifact& rhs) {
  if (lhs.total_cost != rhs.total_cost) return lhs.total_cost < rhs.total_cost;
  if (lhs.hops != rhs.hops) return lhs.hops < rhs.hops;
  if (lhs.regenerations != rhs.regenerations) return lhs.regenerations < rhs.regenerations;
  return lhs.ResourceSequenceKey() < rhs.ResourceSequenceKey();
}

Expected<PlanArtifact> ParsePlanArtifact(std::string_view bytes) {
  if (bytes.size() > kMaxPlanArtifactBytes) {
    return Failure(StatusCode::LimitExceeded, "plan artifact exceeds the permitted maximum size");
  }
  PlanArtifact plan;
  bool header_seen = false;
  bool digest_seen = false;
  Digest256 declared_digest;
  std::size_t cursor = 0;
  std::size_t line_number = 0;
  std::size_t last_segment_index = 0;
  bool have_segment = false;

  while (cursor < bytes.size()) {
    const std::size_t newline = bytes.find('\n', cursor);
    std::string_view line =
        newline == std::string_view::npos ? bytes.substr(cursor) : bytes.substr(cursor, newline - cursor);
    cursor = newline == std::string_view::npos ? bytes.size() : newline + 1;
    ++line_number;
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.empty()) continue;

    const auto tokens = SplitTokens(line);
    if (!tokens.ok()) {
      return Failure(tokens.status().code, "line " + std::to_string(line_number) + ": " + tokens.status().detail);
    }
    const std::vector<std::string>& values = tokens.value();
    const auto fail = [&](const Status& status) -> Expected<PlanArtifact> {
      const Status normalised = NormaliseDecodeStatus(status);
      return Failure(normalised.code, "line " + std::to_string(line_number) + ": " + normalised.detail);
    };

    if (!header_seen) {
      if (values.size() != 2 || values[0] != "OPP-PLAN") {
        return Failure(StatusCode::MalformedInput, "plan must start with the OPP-PLAN magic line");
      }
      auto version = ParseU32(values[1]);
      if (!version.ok()) return fail(version.status());
      if (version.value() != kPlanFormatVersion) {
        return Failure(StatusCode::Unsupported,
                       "plan format revision " + values[1] + " is not supported by this runtime");
      }
      plan.format_version = version.value();
      header_seen = true;
      continue;
    }
    if (digest_seen) {
      return Failure(StatusCode::MalformedInput, "plan content appears after the digest line");
    }

    const std::string& keyword = values[0];
    if (keyword == "digest") {
      if (values.size() != 2) return fail(Failure(StatusCode::MalformedInput, "digest takes one value"));
      auto parsed = Digest256::FromHex(values[1]);
      if (!parsed.ok()) return fail(parsed.status());
      declared_digest = parsed.value();
      plan.digest = declared_digest;
      digest_seen = true;
      continue;
    }
    if (keyword == "rule") {
      if (values.size() != 2) return fail(Failure(StatusCode::MalformedInput, "rule takes one value"));
      auto parsed = ParseU32(values[1]);
      if (!parsed.ok()) return fail(parsed.status());
      plan.rule_version = parsed.value();
      if (plan.rule_version != kPlanningRuleVersion) {
        return Failure(StatusCode::Unsupported,
                       "plan was produced by planning rule revision " + values[1] +
                           ", which this runtime does not reproduce");
      }
      continue;
    }
    if (keyword == "request") {
      if (values.size() != 3) return fail(Failure(StatusCode::MalformedInput, "request takes an id and a digest"));
      auto id = RequestId::Parse(values[1]);
      if (!id.ok()) return fail(id.status());
      auto digest = Digest256::FromHex(values[2]);
      if (!digest.ok()) return fail(digest.status());
      plan.request_id = std::move(id.value());
      plan.request_digest = digest.value();
      continue;
    }
    if (keyword == "snapshot") {
      if (values.size() != 4) {
        return fail(Failure(StatusCode::MalformedInput, "snapshot takes an id, a generation and a digest"));
      }
      auto id = SnapshotId::Parse(values[1]);
      if (!id.ok()) return fail(id.status());
      auto generation = ParseU64(values[2]);
      if (!generation.ok()) return fail(generation.status());
      auto digest = Digest256::FromHex(values[3]);
      if (!digest.ok()) return fail(digest.status());
      plan.snapshot_id = std::move(id.value());
      plan.snapshot_generation = generation.value();
      plan.snapshot_digest = digest.value();
      continue;
    }
    if (keyword == "binding") {
      if (values.size() < 2) return fail(Failure(StatusCode::MalformedInput, "binding takes a source id"));
      auto id = SourceId::Parse(values[1]);
      if (!id.ok()) return fail(id.status());
      auto generation = RequiredRawField(values, 2, "gen");
      if (!generation.ok()) return fail(generation.status());
      auto parsed_generation = ParseU64(generation.value());
      if (!parsed_generation.ok()) return fail(parsed_generation.status());
      auto contribution = RequiredKeyToken(values, 2, "contrib");
      if (!contribution.ok()) return fail(contribution.status());
      auto parsed_contribution = Digest256::FromHex(contribution.value());
      if (!parsed_contribution.ok()) return fail(parsed_contribution.status());
      SourceBinding binding;
      binding.source = std::move(id.value());
      binding.generation = parsed_generation.value();
      binding.snapshot_contribution = parsed_contribution.value();
      plan.bound_sources.push_back(std::move(binding));
      continue;
    }
    if (keyword == "endpoints") {
      auto snode = RequiredKeyToken(values, 1, "snode");
      if (!snode.ok()) return fail(snode.status());
      auto sport = RequiredKeyToken(values, 1, "sport");
      if (!sport.ok()) return fail(sport.status());
      auto dnode = RequiredKeyToken(values, 1, "dnode");
      if (!dnode.ok()) return fail(dnode.status());
      auto dport = RequiredKeyToken(values, 1, "dport");
      if (!dport.ok()) return fail(dport.status());
      auto sn = NodeId::Parse(snode.value());
      if (!sn.ok()) return fail(sn.status());
      auto sp = PortId::Parse(sport.value());
      if (!sp.ok()) return fail(sp.status());
      auto dn = NodeId::Parse(dnode.value());
      if (!dn.ok()) return fail(dn.status());
      auto dp = PortId::Parse(dport.value());
      if (!dp.ok()) return fail(dp.status());
      plan.source = PortKey{std::move(sn.value()), std::move(sp.value())};
      plan.destination = PortKey{std::move(dn.value()), std::move(dp.value())};
      continue;
    }
    if (keyword == "channel") {
      auto width = RequiredRawField(values, 1, "width");
      if (!width.ok()) return fail(width.status());
      auto parsed_width = ParseU16(width.value());
      if (!parsed_width.ok()) return fail(parsed_width.status());
      plan.channel_width_slots = parsed_width.value();
      continue;
    }
    if (keyword == "totals") {
      auto cost = RequiredRawField(values, 1, "cost");
      if (!cost.ok()) return fail(cost.status());
      auto parsed_cost = ParseU64(cost.value());
      if (!parsed_cost.ok()) return fail(parsed_cost.status());
      plan.total_cost = parsed_cost.value();
      auto distance = RequiredRawField(values, 1, "distance");
      if (!distance.ok()) return fail(distance.status());
      auto parsed_distance = ParseU64(distance.value());
      if (!parsed_distance.ok()) return fail(parsed_distance.status());
      plan.total_distance_m = parsed_distance.value();
      auto loss = RequiredRawField(values, 1, "loss");
      if (!loss.ok()) return fail(loss.status());
      auto parsed_loss = ParseDouble(loss.value());
      if (!parsed_loss.ok()) return fail(parsed_loss.status());
      plan.total_loss_db = parsed_loss.value();
      auto hops = RequiredRawField(values, 1, "hops");
      if (!hops.ok()) return fail(hops.status());
      auto parsed_hops = ParseU32(hops.value());
      if (!parsed_hops.ok()) return fail(parsed_hops.status());
      plan.hops = parsed_hops.value();
      auto regen = RequiredRawField(values, 1, "regen");
      if (!regen.ok()) return fail(regen.status());
      auto parsed_regen = ParseU32(regen.value());
      if (!parsed_regen.ok()) return fail(parsed_regen.status());
      plan.regenerations = parsed_regen.value();
      continue;
    }
    if (keyword == "step") {
      if (values.size() < 2) return fail(Failure(StatusCode::MalformedInput, "step takes an index"));
      auto index = ParseU32(values[1]);
      if (!index.ok()) return fail(index.status());
      PlanStep step;
      step.index = index.value();
      auto kind = RequiredKeyToken(values, 2, "kind");
      if (!kind.ok()) return fail(kind.status());
      if (kind.value() == "node") {
        step.kind = StepKind::Node;
      } else if (kind.value() == "port") {
        step.kind = StepKind::Port;
      } else if (kind.value() == "span") {
        step.kind = StepKind::Span;
      } else if (kind.value() == "crossconnect") {
        step.kind = StepKind::CrossConnect;
      } else {
        return fail(Failure(StatusCode::MalformedInput, "step kind '" + kind.value() + "' is not recognised"));
      }
      auto segment = RequiredRawField(values, 2, "seg");
      if (!segment.ok()) return fail(segment.status());
      auto parsed_segment = ParseU32(segment.value());
      if (!parsed_segment.ok()) return fail(parsed_segment.status());
      step.segment_index = parsed_segment.value();
      auto reason = RequiredRawField(values, 2, "reason");
      if (!reason.ok()) return fail(reason.status());
      auto parsed_reason = ParseU32(reason.value());
      if (!parsed_reason.ok()) return fail(parsed_reason.status());
      step.reason_bits = parsed_reason.value();
      auto cost = RequiredRawField(values, 2, "cost");
      if (!cost.ok()) return fail(cost.status());
      auto parsed_step_cost = ParseU64(cost.value());
      if (!parsed_step_cost.ok()) return fail(parsed_step_cost.status());
      step.cost = parsed_step_cost.value();
      auto resource = RequiredKeyToken(values, 2, "res");
      if (!resource.ok()) return fail(resource.status());
      auto parsed_resource = ResourceKeyFromString(resource.value());
      if (!parsed_resource.ok()) return fail(parsed_resource.status());
      step.resource = std::move(parsed_resource.value());
      plan.steps.push_back(std::move(step));
      continue;
    }
    if (keyword == "segment") {
      if (values.size() < 2) return fail(Failure(StatusCode::MalformedInput, "segment takes an index"));
      auto index = ParseU32(values[1]);
      if (!index.ok()) return fail(index.status());
      PlanSegment segment;
      segment.index = index.value();
      auto profile = RequiredKeyToken(values, 2, "profile");
      if (!profile.ok()) return fail(profile.status());
      auto parsed_profile = ProfileId::Parse(profile.value());
      if (!parsed_profile.ok()) return fail(parsed_profile.status());
      segment.profile = std::move(parsed_profile.value());
      auto runs = RequiredRawField(values, 2, "runs");
      if (!runs.ok()) return fail(runs.status());
      auto parsed_runs = ParseU32(runs.value());
      if (!parsed_runs.ok()) return fail(parsed_runs.status());
      segment.channel_runs = parsed_runs.value();
      auto distance = RequiredRawField(values, 2, "distance");
      if (!distance.ok()) return fail(distance.status());
      auto parsed_distance = ParseU64(distance.value());
      if (!parsed_distance.ok()) return fail(parsed_distance.status());
      segment.distance_m = parsed_distance.value();
      auto loss = RequiredRawField(values, 2, "loss");
      if (!loss.ok()) return fail(loss.status());
      auto parsed_loss = ParseDouble(loss.value());
      if (!parsed_loss.ok()) return fail(parsed_loss.status());
      segment.loss_db = parsed_loss.value();
      auto osnr = RequiredRawField(values, 2, "osnr");
      if (!osnr.ok()) return fail(osnr.status());
      auto parsed_osnr = ParseDouble(osnr.value());
      if (!parsed_osnr.ok()) return fail(parsed_osnr.status());
      segment.osnr_db = parsed_osnr.value();
      auto spans = RequiredRawField(values, 2, "spans");
      if (!spans.ok()) return fail(spans.status());
      auto parsed_spans = ParseU32(spans.value());
      if (!parsed_spans.ok()) return fail(parsed_spans.status());
      segment.span_count = parsed_spans.value();
      auto end = RequiredKeyToken(values, 2, "end");
      if (!end.ok()) return fail(end.status());
      if (end.value() == "regeneration") {
        segment.ended_by_regeneration = true;
        auto xc = RequiredKeyToken(values, 2, "xc");
        if (!xc.ok()) return fail(xc.status());
        auto parsed_xc = ResourceKeyFromString(xc.value());
        if (!parsed_xc.ok()) return fail(parsed_xc.status());
        segment.regeneration_resource = std::move(parsed_xc.value());
      } else if (end.value() != "transparent") {
        return fail(Failure(StatusCode::MalformedInput, "segment end must be regeneration or transparent"));
      }
      last_segment_index = segment.index;
      have_segment = true;
      plan.segments.push_back(std::move(segment));
      continue;
    }
    if (keyword == "segspan") {
      if (values.size() < 2) return fail(Failure(StatusCode::MalformedInput, "segspan takes a segment index"));
      auto index = ParseU32(values[1]);
      if (!index.ok()) return fail(index.status());
      if (!have_segment || index.value() >= plan.segments.size()) {
        return fail(Failure(StatusCode::MalformedInput, "segspan appears before its segment record"));
      }
      PlanSpanUse span;
      auto id = RequiredKeyToken(values, 2, "id");
      if (!id.ok()) return fail(id.status());
      auto parsed_id = SpanId::Parse(id.value());
      if (!parsed_id.ok()) return fail(parsed_id.status());
      span.id = std::move(parsed_id.value());
      auto from = RequiredKeyToken(values, 2, "from");
      if (!from.ok()) return fail(from.status());
      auto to = RequiredKeyToken(values, 2, "to");
      if (!to.ok()) return fail(to.status());
      const auto split = [&](const std::string& text, PortKey* out) -> Status {
        const std::size_t colon = text.find(':');
        if (colon == std::string::npos) {
          return Failure(StatusCode::MalformedInput, "port key must be spelled node:port");
        }
        auto node = NodeId::Parse(std::string_view(text).substr(0, colon));
        if (!node.ok()) return node.status();
        auto port = PortId::Parse(std::string_view(text).substr(colon + 1));
        if (!port.ok()) return port.status();
        out->node = std::move(node.value());
        out->port = std::move(port.value());
        return OkStatus();
      };
      Status status = split(from.value(), &span.from);
      if (status.failed()) return fail(status);
      status = split(to.value(), &span.to);
      if (status.failed()) return fail(status);
      auto reversed = RequiredRawField(values, 2, "rev");
      if (!reversed.ok()) return fail(reversed.status());
      auto parsed_reversed = ParseU32(reversed.value());
      if (!parsed_reversed.ok()) return fail(parsed_reversed.status());
      if (parsed_reversed.value() > 1u) return fail(Failure(StatusCode::MalformedInput, "rev must be 0 or 1"));
      span.reversed = parsed_reversed.value() == 1u;
      auto length = RequiredRawField(values, 2, "len");
      if (!length.ok()) return fail(length.status());
      auto parsed_length = ParseU64(length.value());
      if (!parsed_length.ok()) return fail(parsed_length.status());
      span.length_m = parsed_length.value();
      auto loss = RequiredRawField(values, 2, "loss");
      if (!loss.ok()) return fail(loss.status());
      auto parsed_loss = ParseDouble(loss.value());
      if (!parsed_loss.ok()) return fail(parsed_loss.status());
      span.loss_db = parsed_loss.value();
      auto osnr = RequiredRawField(values, 2, "osnr");
      if (!osnr.ok()) return fail(osnr.status());
      auto parsed_osnr = ParseDouble(osnr.value());
      if (!parsed_osnr.ok()) return fail(parsed_osnr.status());
      span.osnr_db = parsed_osnr.value();
      auto cost = RequiredRawField(values, 2, "cost");
      if (!cost.ok()) return fail(cost.status());
      auto parsed_cost = ParseU64(cost.value());
      if (!parsed_cost.ok()) return fail(parsed_cost.status());
      span.cost = parsed_cost.value();
      auto slot = RequiredRawField(values, 2, "slot");
      if (!slot.ok()) return fail(slot.status());
      auto parsed_slot = ParseU16(slot.value());
      if (!parsed_slot.ok()) return fail(parsed_slot.status());
      span.first_slot = parsed_slot.value();
      const auto domains = FindKeyedField(values, 2, "domains");
      if (domains.ok()) {
        auto parsed_domains = ParseDomainList(domains.value());
        if (!parsed_domains.ok()) return fail(parsed_domains.status());
        span.failure_domains = std::move(parsed_domains.value());
      }
      plan.segments[index.value()].spans.push_back(std::move(span));
      continue;
    }
    if (keyword == "reservation") {
      PlanReservation reservation;
      auto resource = RequiredKeyToken(values, 1, "res");
      if (!resource.ok()) return fail(resource.status());
      auto parsed_resource = ResourceKeyFromString(resource.value());
      if (!parsed_resource.ok()) return fail(parsed_resource.status());
      reservation.resource = std::move(parsed_resource.value());
      auto first = RequiredRawField(values, 1, "first");
      if (!first.ok()) return fail(first.status());
      auto parsed_first = ParseU16(first.value());
      if (!parsed_first.ok()) return fail(parsed_first.status());
      reservation.channel.first_slot = parsed_first.value();
      auto width = RequiredRawField(values, 1, "width");
      if (!width.ok()) return fail(width.status());
      auto parsed_width = ParseU16(width.value());
      if (!parsed_width.ok()) return fail(parsed_width.status());
      reservation.channel.width_slots = parsed_width.value();
      auto segment = RequiredRawField(values, 1, "seg");
      if (!segment.ok()) return fail(segment.status());
      auto parsed_segment = ParseU32(segment.value());
      if (!parsed_segment.ok()) return fail(parsed_segment.status());
      reservation.segment_index = parsed_segment.value();
      plan.reservations.push_back(std::move(reservation));
      continue;
    }
    if (keyword == "capability" || keyword == "quality") {
      PlanAssumption assumption;
      auto resource = RequiredKeyToken(values, 1, "res");
      if (!resource.ok()) return fail(resource.status());
      auto parsed_resource = ResourceKeyFromString(resource.value());
      if (!parsed_resource.ok()) return fail(parsed_resource.status());
      assumption.resource = std::move(parsed_resource.value());
      auto field = RequiredKeyToken(values, 1, "field");
      if (!field.ok()) return fail(field.status());
      assumption.field = field.value();
      auto value = RequiredKeyToken(values, 1, "value");
      if (!value.ok()) return fail(value.status());
      assumption.value = value.value();
      if (keyword == "capability") {
        plan.capability_assumptions.push_back(std::move(assumption));
      } else {
        plan.quality_assumptions.push_back(std::move(assumption));
      }
      continue;
    }
    if (keyword == "exposure") {
      FailureDomainExposure exposure;
      auto domain = RequiredKeyToken(values, 1, "domain");
      if (!domain.ok()) return fail(domain.status());
      auto parsed_domain = FailureDomainId::Parse(domain.value());
      if (!parsed_domain.ok()) return fail(parsed_domain.status());
      exposure.id = std::move(parsed_domain.value());
      auto count = RequiredRawField(values, 1, "count");
      if (!count.ok()) return fail(count.status());
      auto parsed_count = ParseU32(count.value());
      if (!parsed_count.ok()) return fail(parsed_count.status());
      exposure.member_count = parsed_count.value();
      auto limit = RequiredRawField(values, 1, "limit");
      if (!limit.ok()) return fail(limit.status());
      auto parsed_limit = ParseU32(limit.value());
      if (!parsed_limit.ok()) return fail(parsed_limit.status());
      exposure.limit = parsed_limit.value();
      plan.failure_domain_exposure.push_back(std::move(exposure));
      continue;
    }
    return fail(Failure(StatusCode::MalformedInput, "unknown plan record '" + keyword + "'"));
  }

  if (!header_seen) return Failure(StatusCode::MalformedInput, "plan is empty");
  if (!digest_seen) return Failure(StatusCode::MalformedInput, "plan is missing its digest line");
  if (plan.steps.empty()) return Failure(StatusCode::MalformedInput, "plan declares no steps");
  if (plan.segments.empty()) return Failure(StatusCode::MalformedInput, "plan declares no transparent segment");
  for (std::size_t i = 0; i < plan.steps.size(); ++i) {
    if (plan.steps[i].index != i) {
      return Failure(StatusCode::MalformedInput, "plan step indices must be dense and ordered from zero");
    }
  }
  for (std::size_t i = 0; i < plan.segments.size(); ++i) {
    if (plan.segments[i].index != i) {
      return Failure(StatusCode::MalformedInput, "plan segment indices must be dense and ordered from zero");
    }
  }
  const Status status = plan.VerifySeal();
  if (status.failed()) return status;
  return plan;
}

}  // namespace opp
