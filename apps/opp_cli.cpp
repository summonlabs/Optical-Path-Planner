// opp: inspection and planning CLI for the Optical Path Planner.
//
// The CLI reads evidence, asks the planner for candidates and reports what it
// found. It never activates, reserves or programs anything.

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "opp/opp.hpp"
#include "opp/synthetic.hpp"

namespace {

using namespace opp;

const char* kUsage =
    "opp - Optical Path Planner inspection utility\n"
    "\n"
    "usage: opp <command> [options]\n"
    "\n"
    "  version\n"
    "      Print the library version and build identification.\n"
    "  selftest\n"
    "      Run the built-in self check (digests, codecs, spectrum rules, a plan).\n"
    "  hash <file>\n"
    "      Print the SHA-256 of a file.\n"
    "  gen --out <file> [--seed N] [--nodes N] [--degree N] [--slots N]\n"
    "      [--grid fixed50|flex12_5] [--clients N] [--no-regenerators]\n"
    "      [--blocking-one-in N] [--generation N] [--id ID]\n"
    "      Write a deterministic SYNTHETIC topology snapshot. Not real evidence.\n"
    "  example --out <file>\n"
    "      Write the small hand-shaped example topology.\n"
    "  snapshot describe <file> [--json]\n"
    "      Summarise a snapshot: counts, digest, coverage and conflicts.\n"
    "  snapshot validate <file>\n"
    "      Parse a snapshot and report whether it is well formed.\n"
    "  plan --snapshot <file> (--request <file> | --from node:port --to node:port)\n"
    "      [--candidates N] [--width N] [--max-regenerations N] [--max-hops N]\n"
    "      [--max-distance M] [--max-spans N] [--max-loss DB] [--min-osnr DB]\n"
    "      [--no-regeneration] [--no-conversion] [--disjointness none|node|span|domain]\n"
    "      [--exclude-node ID] [--exclude-port node:port] [--exclude-span ID]\n"
    "      [--exclude-crossconnect ID] [--exclude-domain ID] [--domain-limit ID:N]\n"
    "      [--require-source ID:GEN] [--snapshot-generation N] [--emit-plan <file>] [--json]\n"
    "      Compute candidates and print the sealed plan artifacts.\n"
    "  validate-plan --snapshot <file> --plan <file> [--accept-restored] [--revalidate]\n"
    "      Check a plan against the evidence generation it is bound to.\n"
    "  store list --root <dir> [--json]\n"
    "  store put --root <dir> --plan <file>\n"
    "  store get --root <dir> --digest <hex> [--out <file>]\n";

struct Arguments {
  std::string command;
  std::vector<std::string> positional;
  std::map<std::string, std::vector<std::string>> options;

  [[nodiscard]] bool Has(const std::string& name) const { return options.find(name) != options.end(); }

  [[nodiscard]] std::optional<std::string> Value(const std::string& name) const {
    const auto found = options.find(name);
    if (found == options.end() || found->second.empty()) return std::nullopt;
    return found->second.back();
  }

  [[nodiscard]] std::vector<std::string> Values(const std::string& name) const {
    const auto found = options.find(name);
    if (found == options.end()) return {};
    return found->second;
  }
};

Expected<Arguments> ParseArguments(int argc, char** argv) {
  Arguments arguments;
  if (argc < 2) {
    return Failure(StatusCode::InvalidArgument, "a command is required");
  }
  arguments.command = argv[1];
  for (int i = 2; i < argc; ++i) {
    const std::string token = argv[i];
    if (token.size() > 2 && token[0] == '-' && token[1] == '-') {
      const std::string name = token.substr(2);
      if (i + 1 < argc && (argv[i + 1][0] != '-' || argv[i + 1][1] == '\0')) {
        arguments.options[name].push_back(argv[i + 1]);
        ++i;
      } else {
        arguments.options[name].push_back(std::string());
      }
    } else {
      arguments.positional.push_back(token);
    }
  }
  return arguments;
}

Expected<std::uint64_t> ParseOptionU64(const Arguments& arguments, const std::string& name,
                                       std::uint64_t fallback) {
  if (!arguments.Has(name)) return fallback;
  const auto value = arguments.Value(name);
  if (!value.has_value()) {
    return Failure(StatusCode::InvalidArgument, "--" + name + " requires a value");
  }
  return ParseU64(value.value());
}

Expected<double> ParseOptionDouble(const Arguments& arguments, const std::string& name) {
  const auto value = arguments.Value(name);
  if (!value.has_value()) {
    return Failure(StatusCode::InvalidArgument, "--" + name + " requires a value");
  }
  return ParseDouble(value.value());
}

Expected<PortKey> ParsePortKey(const std::string& text) {
  const std::size_t colon = text.find(':');
  if (colon == std::string::npos) {
    return Failure(StatusCode::InvalidArgument, "'" + text + "' must be spelled node:port");
  }
  const auto node = NodeId::Parse(std::string_view(text).substr(0, colon));
  if (!node.ok()) return node.status();
  const auto port = PortId::Parse(std::string_view(text).substr(colon + 1));
  if (!port.ok()) return port.status();
  return PortKey{node.value(), port.value()};
}

std::string JsonEscape(const std::string& text) {
  std::string out;
  for (char c : text) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buffer[8];
          std::snprintf(buffer, sizeof(buffer), "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
          out += buffer;
        } else {
          out.push_back(c);
        }
    }
  }
  return out;
}

std::string JsonString(const std::string& text) { return "\"" + JsonEscape(text) + "\""; }

std::string JsonKeyValue(const std::string& key, const std::string& value) {
  return "{" + JsonString(key) + ":" + value + "}";
}

int Report(const Status& status, const std::string& context) {
  std::cerr << context << ": " << StatusCodeName(status.code) << ": " << status.detail << "\n";
  return 1;
}

void PrintSnapshotSummary(const TopologySnapshot& snapshot, bool json) {
  if (!json) {
    std::cout << "snapshot: " << snapshot.id().str() << "\n";
    std::cout << "generation: " << snapshot.generation() << "\n";
    std::cout << "digest: " << snapshot.digest().ToHex() << "\n";
    std::cout << "freshness: " << EvidenceFreshnessName(snapshot.freshness()) << "\n";
    std::cout << "grid: " << GridKindName(snapshot.spectrum().grid)
              << " slots=" << snapshot.spectrum().slot_count << "\n";
    std::cout << "nodes: " << snapshot.nodes().size() << "\n";
    std::cout << "ports: " << snapshot.ports().size() << "\n";
    std::cout << "spans: " << snapshot.spans().size() << "\n";
    std::cout << "cross-connects: " << snapshot.cross_connects().size() << "\n";
    std::cout << "reach profiles: " << snapshot.reach_profiles().size() << "\n";
    std::cout << "directed arcs: " << snapshot.ArcCount() << "\n";
    std::cout << "coverage complete: " << (snapshot.coverage_complete() ? "true" : "false") << "\n";
    for (const SourceRecord& source : snapshot.sources()) {
      std::cout << "source " << source.id.str() << " generation=" << source.generation
                << " coverage=" << CoverageName(source.coverage) << "\n";
    }
    for (const ResourceKey& key : snapshot.conflicted_resources()) {
      std::cout << "conflict " << ResourceKeyToString(key) << "\n";
    }
    for (const ResourceKey& key : snapshot.unresolved_references()) {
      std::cout << "unresolved " << ResourceKeyToString(key) << "\n";
    }
    return;
  }
  std::string out = "{";
  out += "\"id\":" + JsonString(snapshot.id().str());
  out += ",\"generation\":" + std::to_string(snapshot.generation());
  out += ",\"digest\":" + JsonString(snapshot.digest().ToHex());
  out += ",\"freshness\":" + JsonString(EvidenceFreshnessName(snapshot.freshness()));
  out += ",\"grid\":" + JsonString(GridKindName(snapshot.spectrum().grid));
  out += ",\"slots\":" + std::to_string(snapshot.spectrum().slot_count);
  out += ",\"nodes\":" + std::to_string(snapshot.nodes().size());
  out += ",\"ports\":" + std::to_string(snapshot.ports().size());
  out += ",\"spans\":" + std::to_string(snapshot.spans().size());
  out += ",\"cross_connects\":" + std::to_string(snapshot.cross_connects().size());
  out += ",\"reach_profiles\":" + std::to_string(snapshot.reach_profiles().size());
  out += ",\"directed_arcs\":" + std::to_string(snapshot.ArcCount());
  out += ",\"coverage_complete\":";
  out += snapshot.coverage_complete() ? "true" : "false";
  out += ",\"sources\":[";
  for (std::size_t i = 0; i < snapshot.sources().size(); ++i) {
    if (i != 0) out += ",";
    const SourceRecord& source = snapshot.sources()[i];
    out += "{" + JsonString("id") + ":" + JsonString(source.id.str()) + "," + JsonString("generation") + ":" +
           std::to_string(source.generation) + "," + JsonString("coverage") + ":" +
           JsonString(CoverageName(source.coverage)) + "}";
  }
  out += "]";
  out += ",\"conflicts\":[";
  for (std::size_t i = 0; i < snapshot.conflicted_resources().size(); ++i) {
    if (i != 0) out += ",";
    out += JsonString(ResourceKeyToString(snapshot.conflicted_resources()[i]));
  }
  out += "]";
  out += ",\"unresolved\":[";
  for (std::size_t i = 0; i < snapshot.unresolved_references().size(); ++i) {
    if (i != 0) out += ",";
    out += JsonString(ResourceKeyToString(snapshot.unresolved_references()[i]));
  }
  out += "]}";
  std::cout << out << "\n";
}

void PrintResultJson(const PlanningResult& result) {
  std::string out = "{";
  out += "\"outcome\":" + JsonString(PlanOutcomeName(result.outcome));
  out += ",\"status\":" + JsonString(StatusCodeName(result.status.code));
  out += ",\"detail\":" + JsonString(result.status.detail);
  out += ",\"request_digest\":" + JsonString(result.request_digest.ToHex());
  out += ",\"snapshot_digest\":" + JsonString(result.snapshot_digest.ToHex());
  out += ",\"limitations\":" + JsonString(DescribeLimitations(result.limitations));
  out += ",\"optimality_proven\":";
  out += result.optimality_proven ? "true" : "false";
  out += ",\"statistics\":{\"labels_created\":" + std::to_string(result.statistics.labels_created) +
         ",\"labels_expanded\":" + std::to_string(result.statistics.labels_expanded) +
         ",\"labels_dominated\":" + std::to_string(result.statistics.labels_dominated) +
         ",\"states_visited\":" + std::to_string(result.statistics.states_visited) +
         ",\"peak_frontier\":" + std::to_string(result.statistics.peak_frontier) +
         ",\"arcs_examined\":" + std::to_string(result.statistics.arcs_examined) + "}";
  out += ",\"result_digest\":" + JsonString(result.result_digest.ToHex());
  out += ",\"cuts\":[";
  for (std::size_t i = 0; i < result.cuts.size(); ++i) {
    if (i != 0) out += ",";
    out += "{" + JsonString("reason") + ":" + JsonString(CutReasonName(result.cuts[i].reason)) + "," +
           JsonString("count") + ":" + std::to_string(result.cuts[i].count) + "}";
  }
  out += "]";
  out += ",\"witnesses\":[";
  for (std::size_t i = 0; i < result.witnesses.size(); ++i) {
    if (i != 0) out += ",";
    const Witness& witness = result.witnesses[i];
    out += "{" + JsonString("reason") + ":" + JsonString(CutReasonName(witness.reason)) + "," +
           JsonString("resource") + ":" + JsonString(ResourceKeyToString(witness.resource)) + "," +
           JsonString("detail") + ":" + JsonString(witness.detail) + "}";
  }
  out += "]";
  out += ",\"candidates\":[";
  for (std::size_t i = 0; i < result.candidates.size(); ++i) {
    if (i != 0) out += ",";
    const PlanArtifact& plan = result.candidates[i];
    out += "{";
    out += "\"digest\":" + JsonString(plan.DigestHex());
    out += ",\"total_cost\":" + std::to_string(plan.total_cost);
    out += ",\"hops\":" + std::to_string(plan.hops);
    out += ",\"regenerations\":" + std::to_string(plan.regenerations);
    out += ",\"total_distance_m\":" + std::to_string(plan.total_distance_m);
    out += ",\"total_loss_db\":" + JsonString(FormatDouble(plan.total_loss_db).ValueOr(std::string("0")));
    out += ",\"channel_width_slots\":" + std::to_string(plan.channel_width_slots);
    out += ",\"snapshot_digest\":" + JsonString(plan.snapshot_digest.ToHex());
    out += ",\"bound_sources\":[";
    for (std::size_t j = 0; j < plan.bound_sources.size(); ++j) {
      if (j != 0) out += ",";
      out += "{" + JsonString("source") + ":" + JsonString(plan.bound_sources[j].source.str()) + "," +
             JsonString("generation") + ":" + std::to_string(plan.bound_sources[j].generation) + "}";
    }
    out += "]";
    out += ",\"steps\":[";
    for (std::size_t j = 0; j < plan.steps.size(); ++j) {
      if (j != 0) out += ",";
      const PlanStep& step = plan.steps[j];
      out += "{" + JsonString("index") + ":" + std::to_string(step.index) + "," + JsonString("kind") + ":" +
             JsonString(StepKindName(step.kind)) + "," + JsonString("resource") + ":" +
             JsonString(ResourceKeyToString(step.resource)) + "," + JsonString("segment") + ":" +
             std::to_string(step.segment_index) + "," + JsonString("reasons") + ":" +
             JsonString(DescribeEligibility(step.reason_bits)) + "}";
    }
    out += "]";
    out += ",\"segments\":[";
    for (std::size_t j = 0; j < plan.segments.size(); ++j) {
      if (j != 0) out += ",";
      const PlanSegment& segment = plan.segments[j];
      out += "{" + JsonString("index") + ":" + std::to_string(segment.index) + "," + JsonString("profile") + ":" +
             JsonString(segment.profile.str()) + "," + JsonString("span_count") + ":" +
             std::to_string(segment.span_count) + "," + JsonString("channel_runs") + ":" +
             std::to_string(segment.channel_runs) + "," + JsonString("distance_m") + ":" +
             std::to_string(segment.distance_m) + "," + JsonString("osnr_db") + ":" +
             JsonString(FormatDouble(segment.osnr_db).ValueOr(std::string("0"))) + "," +
             JsonString("ended_by_regeneration") + ":" + (segment.ended_by_regeneration ? "true" : "false") + "}";
    }
    out += "]";
    out += ",\"reservations\":[";
    for (std::size_t j = 0; j < plan.reservations.size(); ++j) {
      if (j != 0) out += ",";
      const PlanReservation& reservation = plan.reservations[j];
      out += "{" + JsonString("resource") + ":" + JsonString(ResourceKeyToString(reservation.resource)) + "," +
             JsonString("first_slot") + ":" + std::to_string(reservation.channel.first_slot) + "," +
             JsonString("width_slots") + ":" + std::to_string(reservation.channel.width_slots) + "}";
    }
    out += "]";
    out += ",\"failure_domains\":[";
    for (std::size_t j = 0; j < plan.failure_domain_exposure.size(); ++j) {
      if (j != 0) out += ",";
      const FailureDomainExposure& exposure = plan.failure_domain_exposure[j];
      out += "{" + JsonString("domain") + ":" + JsonString(exposure.id.str()) + "," + JsonString("members") + ":" +
             std::to_string(exposure.member_count) + "," + JsonString("limit") + ":" +
             std::to_string(exposure.limit) + "}";
    }
    out += "]";
    out += "}";
  }
  out += "]}";
  std::cout << out << "\n";
}

int CommandVersion() {
  std::cout << LibraryName() << " " << VersionString() << " (" << BuildIdentification() << ")\n";
  std::cout << "snapshot format " << kSnapshotFormatVersion << ", plan format " << kPlanFormatVersion
            << ", store format " << kStoreFormatVersion << ", transport " << kProtocolVersion
            << ", planning rules " << kPlanningRuleVersion << "\n";
  return 0;
}

int CommandSelfTest() {
  const Status status = SelfTest();
  if (status.failed()) return Report(status, "selftest");
  std::cout << "selftest: " << status.detail << "\n";
  return 0;
}

int CommandHash(const Arguments& arguments) {
  if (arguments.positional.empty()) {
    std::cerr << "hash requires a file path\n";
    return 2;
  }
  const auto bytes = ReadFileBounded(arguments.positional.front(), 1ull << 30);
  if (!bytes.ok()) return Report(bytes.status(), "hash");
  Sha256 hasher;
  hasher.Update(bytes.value());
  std::cout << hasher.Finalize().ToHex() << "  " << arguments.positional.front() << "\n";
  return 0;
}

int CommandGen(const Arguments& arguments) {
  SyntheticOptions options;
  const auto seed = ParseOptionU64(arguments, "seed", options.seed);
  if (!seed.ok()) return Report(seed.status(), "gen");
  options.seed = seed.value();
  const auto nodes = ParseOptionU64(arguments, "nodes", options.node_count);
  if (!nodes.ok()) return Report(nodes.status(), "gen");
  options.node_count = static_cast<std::uint32_t>(nodes.value());
  const auto degree = ParseOptionU64(arguments, "degree", options.degree);
  if (!degree.ok()) return Report(degree.status(), "gen");
  options.degree = static_cast<std::uint32_t>(degree.value());
  const auto slots = ParseOptionU64(arguments, "slots", options.slot_count);
  if (!slots.ok()) return Report(slots.status(), "gen");
  options.slot_count = static_cast<std::uint16_t>(slots.value());
  const auto clients = ParseOptionU64(arguments, "clients", options.client_ports);
  if (!clients.ok()) return Report(clients.status(), "gen");
  options.client_ports = static_cast<std::uint32_t>(clients.value());
  const auto blocking = ParseOptionU64(arguments, "blocking-one-in", options.slot_blocking_one_in);
  if (!blocking.ok()) return Report(blocking.status(), "gen");
  options.slot_blocking_one_in = static_cast<std::uint32_t>(blocking.value());
  const auto generation = ParseOptionU64(arguments, "generation", options.generation);
  if (!generation.ok()) return Report(generation.status(), "gen");
  options.generation = generation.value();
  if (const auto value = arguments.Value("grid"); value.has_value()) {
    if (!ParseGridKind(value.value(), &options.grid)) {
      std::cerr << "gen: grid must be fixed50 or flex12_5\n";
      return 2;
    }
  }
  if (const auto value = arguments.Value("id"); value.has_value()) options.id = value.value();
  options.include_regenerators = !arguments.Has("no-regenerators");

  const auto snapshot = GenerateSyntheticTopology(options);
  if (!snapshot.ok()) return Report(snapshot.status(), "gen");
  const auto out = arguments.Value("out");
  if (!out.has_value()) {
    std::cout << SnapshotToText(snapshot.value());
    return 0;
  }
  const Status status = SaveSnapshotFile(out.value(), snapshot.value());
  if (status.failed()) return Report(status, "gen");
  std::cout << "wrote " << out.value() << " digest=" << snapshot.value().digest().ToHex() << "\n";
  return 0;
}

int CommandExample(const Arguments& arguments) {
  const auto snapshot = BuildExampleTopology();
  if (!snapshot.ok()) return Report(snapshot.status(), "example");
  const auto out = arguments.Value("out");
  if (!out.has_value()) {
    std::cout << SnapshotToText(snapshot.value());
    return 0;
  }
  const Status status = SaveSnapshotFile(out.value(), snapshot.value());
  if (status.failed()) return Report(status, "example");
  std::cout << "wrote " << out.value() << " digest=" << snapshot.value().digest().ToHex() << "\n";
  return 0;
}

int CommandSnapshot(const Arguments& arguments) {
  if (arguments.positional.empty()) {
    std::cerr << "snapshot requires a subcommand\n";
    return 2;
  }
  const std::string& subcommand = arguments.positional.front();
  std::string path;
  if (arguments.positional.size() > 1) path = arguments.positional[1];
  if (path.empty()) {
    const auto value = arguments.Value("file");
    if (value.has_value()) path = value.value();
  }
  if (path.empty()) {
    std::cerr << "snapshot " << subcommand << " requires a file path\n";
    return 2;
  }
  const auto snapshot = LoadSnapshotFile(path);
  if (!snapshot.ok()) return Report(snapshot.status(), "snapshot");
  if (subcommand == "validate") {
    std::cout << "ok " << path << " digest=" << snapshot.value().digest().ToHex() << "\n";
    return 0;
  }
  if (subcommand == "describe") {
    PrintSnapshotSummary(snapshot.value(), arguments.Has("json"));
    return 0;
  }
  std::cerr << "unknown snapshot subcommand '" << subcommand << "'\n";
  return 2;
}

Expected<PlanningRequest> BuildRequest(const Arguments& arguments) {
  PlanningRequest request;
  request.id = RequestId::Trusted("cli");
  const auto request_file = arguments.Value("request");
  if (request_file.has_value()) {
    const auto bytes = ReadFileBounded(request_file.value(), kMaxTextLineBytes * 4096ull);
    if (!bytes.ok()) return bytes.status();
    const auto parsed = ParseRequestText(bytes.value());
    if (!parsed.ok()) return parsed.status();
    request = parsed.value();
  } else {
    const auto from = arguments.Value("from");
    const auto to = arguments.Value("to");
    if (!from.has_value() || !to.has_value()) {
      return Failure(StatusCode::InvalidArgument, "plan requires either --request or both --from and --to");
    }
    const auto source = ParsePortKey(from.value());
    if (!source.ok()) return source.status();
    const auto destination = ParsePortKey(to.value());
    if (!destination.ok()) return destination.status();
    request.source = source.value();
    request.destination = destination.value();
  }

  if (const auto value = arguments.Value("candidates"); value.has_value()) {
    const auto parsed = ParseU32(value.value());
    if (!parsed.ok()) return parsed.status();
    request.max_candidates = parsed.value();
  }
  if (const auto value = arguments.Value("width"); value.has_value()) {
    const auto parsed = ParseU16(value.value());
    if (!parsed.ok()) return parsed.status();
    request.channel_width_slots = parsed.value();
  }
  if (const auto value = arguments.Value("max-regenerations"); value.has_value()) {
    const auto parsed = ParseU32(value.value());
    if (!parsed.ok()) return parsed.status();
    request.max_regenerations = parsed.value();
  }
  if (const auto value = arguments.Value("max-hops"); value.has_value()) {
    const auto parsed = ParseU32(value.value());
    if (!parsed.ok()) return parsed.status();
    request.max_hops = parsed.value();
  }
  if (arguments.Has("no-regeneration")) request.constraints.allow_regeneration = false;
  if (arguments.Has("no-conversion")) request.constraints.allow_wavelength_conversion = false;
  if (const auto value = arguments.Value("disjointness"); value.has_value()) {
    if (!ParseDisjointness(value.value(), &request.disjointness)) {
      return Failure(StatusCode::InvalidArgument, "--disjointness must be none, node, span or domain");
    }
  }
  for (const std::string& value : arguments.Values("exclude-node")) {
    const auto id = NodeId::Parse(value);
    if (!id.ok()) return id.status();
    request.constraints.excluded_nodes.push_back(id.value());
  }
  for (const std::string& value : arguments.Values("exclude-span")) {
    const auto id = SpanId::Parse(value);
    if (!id.ok()) return id.status();
    request.constraints.excluded_spans.push_back(id.value());
  }
  for (const std::string& value : arguments.Values("exclude-crossconnect")) {
    const auto id = CrossConnectId::Parse(value);
    if (!id.ok()) return id.status();
    request.constraints.excluded_cross_connects.push_back(id.value());
  }
  for (const std::string& value : arguments.Values("exclude-domain")) {
    const auto id = FailureDomainId::Parse(value);
    if (!id.ok()) return id.status();
    request.constraints.excluded_failure_domains.push_back(id.value());
  }
  for (const std::string& value : arguments.Values("exclude-port")) {
    const auto key = ParsePortKey(value);
    if (!key.ok()) return key.status();
    request.constraints.excluded_ports.push_back(key.value());
  }
  for (const std::string& value : arguments.Values("domain-limit")) {
    const std::size_t colon = value.rfind(':');
    if (colon == std::string::npos) {
      return Failure(StatusCode::InvalidArgument, "--domain-limit must be spelled domain:count");
    }
    const auto id = FailureDomainId::Parse(std::string_view(value).substr(0, colon));
    if (!id.ok()) return id.status();
    const auto limit = ParseU32(std::string_view(value).substr(colon + 1));
    if (!limit.ok()) return limit.status();
    request.constraints.max_members_per_failure_domain[id.value()] = limit.value();
  }
  for (const std::string& value : arguments.Values("require-source")) {
    const std::size_t colon = value.rfind(':');
    if (colon == std::string::npos) {
      return Failure(StatusCode::InvalidArgument, "--require-source must be spelled source:generation");
    }
    const auto id = SourceId::Parse(std::string_view(value).substr(0, colon));
    if (!id.ok()) return id.status();
    const auto generation = ParseU64(std::string_view(value).substr(colon + 1));
    if (!generation.ok()) return generation.status();
    request.required_source_generations[id.value()] = generation.value();
  }
  if (arguments.Has("snapshot-generation")) {
    const auto value = ParseOptionU64(arguments, "snapshot-generation", 0);
    if (!value.ok()) return value.status();
    request.required_snapshot_generation = value.value();
  }
  if (arguments.Has("max-distance")) {
    const auto value = ParseOptionU64(arguments, "max-distance", 0);
    if (!value.ok()) return value.status();
    request.constraints.max_total_distance_m = value.value();
  }
  if (arguments.Has("max-spans")) {
    const auto value = ParseOptionU64(arguments, "max-spans", 0);
    if (!value.ok()) return value.status();
    request.constraints.max_total_span_count = static_cast<std::uint32_t>(value.value());
  }
  if (arguments.Has("max-loss")) {
    const auto value = ParseOptionDouble(arguments, "max-loss");
    if (!value.ok()) return value.status();
    request.constraints.max_total_loss_db = value.value();
  }
  if (arguments.Has("min-osnr")) {
    const auto value = ParseOptionDouble(arguments, "min-osnr");
    if (!value.ok()) return value.status();
    request.constraints.min_segment_osnr_db = value.value();
  }
  return request;
}

int CommandPlan(const Arguments& arguments) {
  const auto snapshot_path = arguments.Value("snapshot");
  if (!snapshot_path.has_value()) {
    std::cerr << "plan requires --snapshot\n";
    return 2;
  }
  const auto snapshot = LoadSnapshotFile(snapshot_path.value());
  if (!snapshot.ok()) return Report(snapshot.status(), "plan");

  const auto request = BuildRequest(arguments);
  if (!request.ok()) return Report(request.status(), "plan");

  const Planner planner;
  const PlanningResult result = planner.Plan(snapshot.value(), request.value());

  // Emitting the sealed artifact is the only way a caller can hand a plan to
  // another process; the plan is a recommendation, never an authority.
  if (const auto emit = arguments.Value("emit-plan"); emit.has_value()) {
    for (std::size_t i = 0; i < result.candidates.size(); ++i) {
      const std::string path = i == 0 ? emit.value() : emit.value() + "." + std::to_string(i);
      const Status status = WriteFileAtomic(path, result.candidates[i].CanonicalBytes());
      if (status.failed()) return Report(status, "plan --emit-plan");
      std::cout << "wrote " << path << " digest=" << result.candidates[i].DigestHex() << "\n";
    }
  }

  if (arguments.Has("json")) {
    PrintResultJson(result);
  } else {
    std::cout << result.ExplainText();
  }
  switch (result.outcome) {
    case PlanOutcome::Feasible:
      return 0;
    case PlanOutcome::Infeasible:
      return 3;
    case PlanOutcome::Indeterminate:
      return 4;
    case PlanOutcome::Unsupported:
      return 5;
    case PlanOutcome::Cancelled:
      return 6;
    case PlanOutcome::Refused:
      return 7;
  }
  return 7;
}

int CommandValidatePlan(const Arguments& arguments) {
  const auto snapshot_path = arguments.Value("snapshot");
  const auto plan_path = arguments.Value("plan");
  if (!snapshot_path.has_value() || !plan_path.has_value()) {
    std::cerr << "validate-plan requires --snapshot and --plan\n";
    return 2;
  }
  const auto snapshot = LoadSnapshotFile(snapshot_path.value());
  if (!snapshot.ok()) return Report(snapshot.status(), "validate-plan");
  const auto bytes = ReadFileBounded(plan_path.value(), kMaxPlanArtifactBytes);
  if (!bytes.ok()) return Report(bytes.status(), "validate-plan");
  const auto plan = ParsePlanArtifact(bytes.value());
  if (!plan.ok()) return Report(plan.status(), "validate-plan");

  ValidationPolicy policy;
  policy.accept_restored_evidence = arguments.Has("accept-restored");
  policy.revalidate_on_mismatch = arguments.Has("revalidate");
  const ValidationReport report =
      policy.revalidate_on_mismatch
          ? RevalidatePlan(plan.value(), snapshot.value(), policy)
          : ValidatePlanBindings(plan.value(), snapshot.value(), policy);
  std::cout << report.ExplainText();
  return report.ok() ? 0 : 8;
}

int CommandStore(const Arguments& arguments) {
  if (arguments.positional.empty()) {
    std::cerr << "store requires a subcommand\n";
    return 2;
  }
  const std::string& subcommand = arguments.positional.front();
  const auto root = arguments.Value("root");
  if (!root.has_value()) {
    std::cerr << "store " << subcommand << " requires --root\n";
    return 2;
  }
  StoreOptions options;
  options.root = root.value();
  if (const auto value = ParseOptionU64(arguments, "max-plans", options.max_plans); value.ok()) {
    options.max_plans = static_cast<std::uint32_t>(value.value());
  } else {
    return Report(value.status(), "store");
  }
  const auto store = PlanStore::Open(options);
  if (!store.ok()) return Report(store.status(), "store");

  if (subcommand == "list") {
    std::vector<StoreEntry> entries;
    std::vector<std::string> rejected;
    const Status status = store.value()->List(&entries, &rejected);
    if (status.failed()) return Report(status, "store list");
    if (arguments.Has("json")) {
      std::string out = "{\"plans\":[";
      for (std::size_t i = 0; i < entries.size(); ++i) {
        if (i != 0) out += ",";
        out += "{" + JsonString("digest") + ":" + JsonString(entries[i].digest.ToHex()) + "," +
               JsonString("bytes") + ":" + std::to_string(entries[i].bytes) + "," + JsonString("request") + ":" +
               JsonString(entries[i].request_id.str()) + "}";
      }
      out += "],\"rejected\":[";
      for (std::size_t i = 0; i < rejected.size(); ++i) {
        if (i != 0) out += ",";
        out += JsonString(rejected[i]);
      }
      out += "]}";
      std::cout << out << "\n";
    } else {
      for (const StoreEntry& entry : entries) {
        std::cout << entry.digest.ToHex() << " " << entry.bytes << " " << entry.request_id.str() << "\n";
      }
      for (const std::string& name : rejected) {
        std::cout << "rejected " << name << "\n";
      }
      std::cout << "total " << entries.size() << "\n";
    }
    return 0;
  }
  if (subcommand == "put") {
    const auto plan_path = arguments.Value("plan");
    if (!plan_path.has_value()) {
      std::cerr << "store put requires --plan\n";
      return 2;
    }
    const auto bytes = ReadFileBounded(plan_path.value(), kMaxPlanArtifactBytes);
    if (!bytes.ok()) return Report(bytes.status(), "store put");
    const auto plan = ParsePlanArtifact(bytes.value());
    if (!plan.ok()) return Report(plan.status(), "store put");
    const Status status = store.value()->Put(plan.value());
    if (status.failed()) return Report(status, "store put");
    std::cout << "stored " << plan.value().DigestHex() << "\n";
    return 0;
  }
  if (subcommand == "get") {
    const auto digest = arguments.Value("digest");
    if (!digest.has_value()) {
      std::cerr << "store get requires --digest\n";
      return 2;
    }
    const auto plan = store.value()->GetByHex(digest.value());
    if (!plan.ok()) return Report(plan.status(), "store get");
    const auto out = arguments.Value("out");
    if (out.has_value()) {
      const Status status = WriteFileAtomic(out.value(), plan.value().CanonicalBytes());
      if (status.failed()) return Report(status, "store get");
      std::cout << "wrote " << out.value() << "\n";
    } else {
      std::cout << plan.value().CanonicalBytes();
    }
    return 0;
  }
  std::cerr << "unknown store subcommand '" << subcommand << "'\n";
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  const auto arguments = ParseArguments(argc, argv);
  if (!arguments.ok()) {
    std::cerr << kUsage;
    return 2;
  }
  const std::string& command = arguments.value().command;
  if (command == "help" || command == "--help" || command == "-h") {
    std::cout << kUsage;
    return 0;
  }
  if (command == "version") return CommandVersion();
  if (command == "selftest") return CommandSelfTest();
  if (command == "hash") return CommandHash(arguments.value());
  if (command == "gen") return CommandGen(arguments.value());
  if (command == "example") return CommandExample(arguments.value());
  if (command == "snapshot") return CommandSnapshot(arguments.value());
  if (command == "plan") return CommandPlan(arguments.value());
  if (command == "validate-plan") return CommandValidatePlan(arguments.value());
  if (command == "store") return CommandStore(arguments.value());
  std::cerr << "unknown command '" << command << "'\n\n" << kUsage;
  return 2;
}
