#include "opp/request_io.hpp"

#include <algorithm>
#include <string>
#include <vector>

#include "opp/canonical.hpp"
#include "opp/sha256.hpp"

namespace opp {
namespace {

Expected<std::string> Field(const std::vector<std::string>& tokens, std::size_t index, const char* what) {
  if (index >= tokens.size()) {
    return Failure(StatusCode::MalformedInput, std::string("record is missing the ") + what + " value");
  }
  return tokens[index];
}

}  // namespace

std::string RequestToText(const PlanningRequest& request) {
  std::string out;
  out += kRequestMagic;
  out += " ";
  out += FormatU32(kRequestFormatVersion);
  out += "\n";
  const auto emit = [&out](const LineAssembler& line) {
    out += line.text();
    out += "\n";
  };
  {
    LineAssembler line("id");
    line.Add(request.id.str());
    emit(line);
  }
  {
    LineAssembler line("source");
    line.Add(request.source.node.str());
    line.Add(request.source.port.str());
    emit(line);
  }
  {
    LineAssembler line("destination");
    line.Add(request.destination.node.str());
    line.Add(request.destination.port.str());
    emit(line);
  }
  {
    LineAssembler line("width");
    line.AddU16(request.channel_width_slots);
    emit(line);
  }
  {
    LineAssembler line("candidates");
    line.AddU32(request.max_candidates);
    emit(line);
  }
  {
    LineAssembler line("regenerations");
    line.AddU32(request.max_regenerations);
    emit(line);
  }
  {
    LineAssembler line("hops");
    line.AddU32(request.max_hops);
    emit(line);
  }
  if (request.max_total_cost.has_value()) {
    LineAssembler line("cost");
    line.AddU64(request.max_total_cost.value());
    emit(line);
  }
  {
    LineAssembler line("disjointness");
    line.Add(DisjointnessName(request.disjointness));
    emit(line);
  }
  {
    LineAssembler line("accept-restored-evidence");
    line.Add(request.accept_restored_evidence ? "true" : "false");
    emit(line);
  }
  {
    LineAssembler line("search-expansions");
    line.AddU64(request.max_search_expansions);
    emit(line);
  }
  {
    LineAssembler line("search-labels");
    line.AddU64(request.max_search_labels);
    emit(line);
  }
  for (const auto& entry : request.required_source_generations) {
    LineAssembler line("srcgen");
    line.Add(entry.first.str());
    line.AddU64(entry.second);
    emit(line);
  }
  if (request.required_snapshot_generation.has_value()) {
    LineAssembler line("snapshot-generation");
    line.AddU64(request.required_snapshot_generation.value());
    emit(line);
  }
  if (request.expected_snapshot_digest.has_value()) {
    LineAssembler line("snapshot-digest");
    line.Add(request.expected_snapshot_digest.value().ToHex());
    emit(line);
  }
  for (const NodeId& id : request.constraints.excluded_nodes) {
    LineAssembler line("exclude-node");
    line.Add(id.str());
    emit(line);
  }
  for (const PortKey& key : request.constraints.excluded_ports) {
    LineAssembler line("exclude-port");
    line.Add(key.node.str());
    line.Add(key.port.str());
    emit(line);
  }
  for (const SpanId& id : request.constraints.excluded_spans) {
    LineAssembler line("exclude-span");
    line.Add(id.str());
    emit(line);
  }
  for (const CrossConnectId& id : request.constraints.excluded_cross_connects) {
    LineAssembler line("exclude-crossconnect");
    line.Add(id.str());
    emit(line);
  }
  for (const FailureDomainId& id : request.constraints.excluded_failure_domains) {
    LineAssembler line("exclude-domain");
    line.Add(id.str());
    emit(line);
  }
  for (const auto& entry : request.constraints.max_members_per_failure_domain) {
    LineAssembler line("domain-limit");
    line.Add(entry.first.str());
    line.AddU32(entry.second);
    emit(line);
  }
  if (request.constraints.max_total_distance_m.has_value()) {
    LineAssembler line("max-distance");
    line.AddU64(request.constraints.max_total_distance_m.value());
    emit(line);
  }
  if (request.constraints.max_total_span_count.has_value()) {
    LineAssembler line("max-spans");
    line.AddU32(request.constraints.max_total_span_count.value());
    emit(line);
  }
  if (request.constraints.max_total_loss_db.has_value()) {
    LineAssembler line("max-loss");
    line.AddDouble(request.constraints.max_total_loss_db.value());
    emit(line);
  }
  if (request.constraints.min_segment_osnr_db.has_value()) {
    LineAssembler line("min-osnr");
    line.AddDouble(request.constraints.min_segment_osnr_db.value());
    emit(line);
  }
  {
    LineAssembler line("allow-regeneration");
    line.Add(request.constraints.allow_regeneration ? "true" : "false");
    emit(line);
  }
  {
    LineAssembler line("allow-conversion");
    line.Add(request.constraints.allow_wavelength_conversion ? "true" : "false");
    emit(line);
  }
  {
    LineAssembler line("require-spectrum-continuity-across-regeneration");
    line.Add(request.constraints.require_spectrum_continuity_across_regeneration ? "true" : "false");
    emit(line);
  }
  {
    LineAssembler line("allow-repeated-resources");
    line.Add(request.constraints.allow_repeated_resources ? "true" : "false");
    emit(line);
  }
  return out;
}

Digest256 ComputeRequestDigest(const PlanningRequest& request) {
  Sha256 hasher;
  hasher.Update(kRequestDigestDomain);
  hasher.Update("\n");
  hasher.Update(RequestToText(request));
  return hasher.Finalize();
}

std::string RequestCanonicalBytes(const PlanningRequest& request) { return RequestToText(request); }

Expected<PlanningRequest> ParseRequestText(std::string_view text) {
  PlanningRequest request;
  bool header_seen = false;
  bool have_id = false;
  bool have_source = false;
  bool have_destination = false;

  std::size_t cursor = 0;
  std::size_t line_number = 0;
  while (cursor < text.size()) {
    const std::size_t newline = text.find('\n', cursor);
    std::string_view line =
        newline == std::string_view::npos ? text.substr(cursor) : text.substr(cursor, newline - cursor);
    cursor = newline == std::string_view::npos ? text.size() : newline + 1;
    ++line_number;
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.empty()) continue;

    const auto tokens = SplitTokens(line);
    if (!tokens.ok()) {
      return Failure(tokens.status().code, "line " + std::to_string(line_number) + ": " + tokens.status().detail);
    }
    const std::vector<std::string>& values = tokens.value();

    if (!header_seen) {
      if (values.size() != 2 || values[0] != kRequestMagic) {
        return Failure(StatusCode::MalformedInput, "request must start with the OPP-REQUEST magic line");
      }
      const auto version = ParseU32(values[1]);
      if (!version.ok()) return version.status();
      if (version.value() != kRequestFormatVersion) {
        return Failure(StatusCode::Unsupported,
                       "request format revision " + values[1] + " is not supported by this runtime");
      }
      header_seen = true;
      continue;
    }

    const std::string& keyword = values[0];
    const auto fail = [&](const Status& status) -> Expected<PlanningRequest> {
      const Status normalised = NormaliseDecodeStatus(status);
      return Failure(normalised.code, "line " + std::to_string(line_number) + ": " + normalised.detail);
    };

    if (keyword == "id") {
      auto text_value = Field(values, 1, "id");
      if (!text_value.ok()) return fail(text_value.status());
      auto id = RequestId::Parse(text_value.value());
      if (!id.ok()) return fail(id.status());
      request.id = std::move(id.value());
      have_id = true;
      continue;
    }
    if (keyword == "source" || keyword == "destination") {
      auto node_text = Field(values, 1, "node");
      if (!node_text.ok()) return fail(node_text.status());
      auto port_text = Field(values, 2, "port");
      if (!port_text.ok()) return fail(port_text.status());
      auto node = NodeId::Parse(node_text.value());
      if (!node.ok()) return fail(node.status());
      auto port = PortId::Parse(port_text.value());
      if (!port.ok()) return fail(port.status());
      PortKey key{std::move(node.value()), std::move(port.value())};
      if (keyword == "source") {
        request.source = std::move(key);
        have_source = true;
      } else {
        request.destination = std::move(key);
        have_destination = true;
      }
      continue;
    }
    if (keyword == "width" || keyword == "candidates" || keyword == "regenerations" || keyword == "hops" ||
        keyword == "search-expansions" || keyword == "search-labels" || keyword == "max-distance" ||
        keyword == "max-spans") {
      auto value_text = Field(values, 1, keyword.c_str());
      if (!value_text.ok()) return fail(value_text.status());
      const auto parse_u64 = [&](std::uint64_t* out) -> Status {
        auto parsed = ParseU64(value_text.value());
        if (!parsed.ok()) return parsed.status();
        *out = parsed.value();
        return OkStatus();
      };
      const auto parse_u32 = [&](std::uint32_t* out) -> Status {
        auto parsed = ParseU32(value_text.value());
        if (!parsed.ok()) return parsed.status();
        *out = parsed.value();
        return OkStatus();
      };
      std::uint64_t wide = 0;
      std::uint32_t narrow = 0;
      Status status = OkStatus();
      if (keyword == "width") {
        auto parsed = ParseU16(value_text.value());
        if (!parsed.ok()) return fail(parsed.status());
        request.channel_width_slots = parsed.value();
      } else if (keyword == "candidates") {
        status = parse_u32(&narrow);
        request.max_candidates = narrow;
      } else if (keyword == "regenerations") {
        status = parse_u32(&narrow);
        request.max_regenerations = narrow;
      } else if (keyword == "hops") {
        status = parse_u32(&narrow);
        request.max_hops = narrow;
      } else if (keyword == "search-expansions") {
        status = parse_u64(&wide);
        request.max_search_expansions = wide;
      } else if (keyword == "search-labels") {
        status = parse_u64(&wide);
        request.max_search_labels = wide;
      } else if (keyword == "max-distance") {
        status = parse_u64(&wide);
        request.constraints.max_total_distance_m = wide;
      } else if (keyword == "max-spans") {
        status = parse_u32(&narrow);
        request.constraints.max_total_span_count = narrow;
      }
      if (status.failed()) return fail(status);
      continue;
    }
    if (keyword == "cost") {
      auto value_text = Field(values, 1, "cost");
      if (!value_text.ok()) return fail(value_text.status());
      auto parsed = ParseU64(value_text.value());
      if (!parsed.ok()) return fail(parsed.status());
      request.max_total_cost = parsed.value();
      continue;
    }
    if (keyword == "snapshot-generation") {
      auto value_text = Field(values, 1, "snapshot-generation");
      if (!value_text.ok()) return fail(value_text.status());
      auto parsed = ParseU64(value_text.value());
      if (!parsed.ok()) return fail(parsed.status());
      request.required_snapshot_generation = parsed.value();
      continue;
    }
    if (keyword == "snapshot-digest") {
      auto value_text = Field(values, 1, "snapshot-digest");
      if (!value_text.ok()) return fail(value_text.status());
      auto parsed = Digest256::FromHex(value_text.value());
      if (!parsed.ok()) return fail(parsed.status());
      request.expected_snapshot_digest = parsed.value();
      continue;
    }
    if (keyword == "disjointness") {
      auto value_text = Field(values, 1, "disjointness");
      if (!value_text.ok()) return fail(value_text.status());
      Disjointness value = Disjointness::None;
      if (!ParseDisjointness(value_text.value(), &value)) {
        return fail(Failure(StatusCode::MalformedInput, "disjointness token is not recognised"));
      }
      request.disjointness = value;
      continue;
    }
    if (keyword == "srcgen") {
      auto id_text = Field(values, 1, "source");
      if (!id_text.ok()) return fail(id_text.status());
      auto gen_text = Field(values, 2, "generation");
      if (!gen_text.ok()) return fail(gen_text.status());
      auto id = SourceId::Parse(id_text.value());
      if (!id.ok()) return fail(id.status());
      auto generation = ParseU64(gen_text.value());
      if (!generation.ok()) return fail(generation.status());
      request.required_source_generations[id.value()] = generation.value();
      continue;
    }
    if (keyword == "exclude-node" || keyword == "exclude-span" || keyword == "exclude-crossconnect" ||
        keyword == "exclude-domain") {
      auto id_text = Field(values, 1, keyword.c_str());
      if (!id_text.ok()) return fail(id_text.status());
      if (keyword == "exclude-node") {
        auto id = NodeId::Parse(id_text.value());
        if (!id.ok()) return fail(id.status());
        request.constraints.excluded_nodes.push_back(std::move(id.value()));
      } else if (keyword == "exclude-span") {
        auto id = SpanId::Parse(id_text.value());
        if (!id.ok()) return fail(id.status());
        request.constraints.excluded_spans.push_back(std::move(id.value()));
      } else if (keyword == "exclude-crossconnect") {
        auto id = CrossConnectId::Parse(id_text.value());
        if (!id.ok()) return fail(id.status());
        request.constraints.excluded_cross_connects.push_back(std::move(id.value()));
      } else {
        auto id = FailureDomainId::Parse(id_text.value());
        if (!id.ok()) return fail(id.status());
        request.constraints.excluded_failure_domains.push_back(std::move(id.value()));
      }
      continue;
    }
    if (keyword == "exclude-port") {
      auto node_text = Field(values, 1, "node");
      if (!node_text.ok()) return fail(node_text.status());
      auto port_text = Field(values, 2, "port");
      if (!port_text.ok()) return fail(port_text.status());
      auto node = NodeId::Parse(node_text.value());
      if (!node.ok()) return fail(node.status());
      auto port = PortId::Parse(port_text.value());
      if (!port.ok()) return fail(port.status());
      request.constraints.excluded_ports.push_back(PortKey{std::move(node.value()), std::move(port.value())});
      continue;
    }
    if (keyword == "domain-limit") {
      auto id_text = Field(values, 1, "domain");
      if (!id_text.ok()) return fail(id_text.status());
      auto limit_text = Field(values, 2, "limit");
      if (!limit_text.ok()) return fail(limit_text.status());
      auto id = FailureDomainId::Parse(id_text.value());
      if (!id.ok()) return fail(id.status());
      auto limit = ParseU32(limit_text.value());
      if (!limit.ok()) return fail(limit.status());
      request.constraints.max_members_per_failure_domain[id.value()] = limit.value();
      continue;
    }
    if (keyword == "max-loss" || keyword == "min-osnr") {
      auto value_text = Field(values, 1, keyword.c_str());
      if (!value_text.ok()) return fail(value_text.status());
      auto parsed = ParseDouble(value_text.value());
      if (!parsed.ok()) return fail(parsed.status());
      if (keyword == "max-loss") {
        request.constraints.max_total_loss_db = parsed.value();
      } else {
        request.constraints.min_segment_osnr_db = parsed.value();
      }
      continue;
    }
    if (keyword == "accept-restored-evidence" || keyword == "allow-regeneration" || keyword == "allow-conversion" ||
        keyword == "require-spectrum-continuity-across-regeneration" || keyword == "allow-repeated-resources") {
      auto value_text = Field(values, 1, keyword.c_str());
      if (!value_text.ok()) return fail(value_text.status());
      auto parsed = ParseBoolToken(value_text.value());
      if (!parsed.ok()) return fail(parsed.status());
      if (keyword == "accept-restored-evidence") {
        request.accept_restored_evidence = parsed.value();
      } else if (keyword == "allow-regeneration") {
        request.constraints.allow_regeneration = parsed.value();
      } else if (keyword == "allow-conversion") {
        request.constraints.allow_wavelength_conversion = parsed.value();
      } else if (keyword == "require-spectrum-continuity-across-regeneration") {
        request.constraints.require_spectrum_continuity_across_regeneration = parsed.value();
      } else {
        request.constraints.allow_repeated_resources = parsed.value();
      }
      continue;
    }
    return fail(Failure(StatusCode::MalformedInput, "unknown request record '" + keyword + "'"));
  }

  if (!header_seen) return Failure(StatusCode::MalformedInput, "request is empty");
  if (!have_id) return Failure(StatusCode::MalformedInput, "request id is missing");
  if (!have_source) return Failure(StatusCode::MalformedInput, "request source is missing");
  if (!have_destination) return Failure(StatusCode::MalformedInput, "request destination is missing");
  return request;
}

std::string ValidationPolicyToText(const ValidationPolicy& policy) {
  std::string out;
  out += "OPP-VALIDATION-POLICY 1\n";
  {
    LineAssembler line("accept-restored-evidence");
    line.Add(policy.accept_restored_evidence ? "true" : "false");
    out += line.text();
    out += "\n";
  }
  {
    LineAssembler line("revalidate-on-mismatch");
    line.Add(policy.revalidate_on_mismatch ? "true" : "false");
    out += line.text();
    out += "\n";
  }
  return out;
}

Expected<ValidationPolicy> ParseValidationPolicyText(std::string_view text) {
  ValidationPolicy policy;
  bool header_seen = false;
  std::size_t cursor = 0;
  while (cursor < text.size()) {
    const std::size_t newline = text.find('\n', cursor);
    std::string_view line =
        newline == std::string_view::npos ? text.substr(cursor) : text.substr(cursor, newline - cursor);
    cursor = newline == std::string_view::npos ? text.size() : newline + 1;
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.empty()) continue;
    const auto tokens = SplitTokens(line);
    if (!tokens.ok()) return tokens.status();
    const std::vector<std::string>& values = tokens.value();
    if (!header_seen) {
      if (values.size() != 2 || values[0] != "OPP-VALIDATION-POLICY") {
        return Failure(StatusCode::MalformedInput, "policy must start with the OPP-VALIDATION-POLICY magic line");
      }
      header_seen = true;
      continue;
    }
    auto value_text = Field(values, 1, values[0].c_str());
    if (!value_text.ok()) return value_text.status();
    auto parsed = ParseBoolToken(value_text.value());
    if (!parsed.ok()) return parsed.status();
    if (values[0] == "accept-restored-evidence") {
      policy.accept_restored_evidence = parsed.value();
    } else if (values[0] == "revalidate-on-mismatch") {
      policy.revalidate_on_mismatch = parsed.value();
    } else {
      return Failure(StatusCode::MalformedInput, "unknown validation policy record '" + values[0] + "'");
    }
  }
  if (!header_seen) return Failure(StatusCode::MalformedInput, "validation policy is empty");
  return policy;
}

}  // namespace opp
