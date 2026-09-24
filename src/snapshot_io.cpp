#include "opp/snapshot_io.hpp"

#include <string>
#include <utility>
#include <vector>

#include "opp/fileio.hpp"
#include "opp/canonical.hpp"
#include "opp/limits.hpp"
#include "opp/sha256.hpp"
#include "opp/version.hpp"

namespace opp {
namespace {

constexpr std::string_view kUnknown = "unknown";
constexpr std::string_view kConflicting = "conflicting";
constexpr std::string_view kAbsent = "-";

std::string JoinDomains(const std::vector<FailureDomainId>& domains) {
  std::string joined;
  for (std::size_t i = 0; i < domains.size(); ++i) {
    if (i != 0) joined.push_back(',');
    joined += domains[i].str();
  }
  return joined;
}

Expected<std::vector<FailureDomainId>> ParseDomains(std::string_view text) {
  std::vector<FailureDomainId> domains;
  if (text.empty()) return domains;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t comma = text.find(',', start);
    const std::string_view piece =
        comma == std::string_view::npos ? text.substr(start) : text.substr(start, comma - start);
    auto id = FailureDomainId::Parse(piece);
    if (!id.ok()) {
      return Failure(StatusCode::MalformedInput, "failure domain list contains an invalid identifier");
    }
    domains.push_back(std::move(id.value()));
    if (domains.size() > kMaxDomainsPerResource) {
      return Failure(StatusCode::LimitExceeded, "failure domain list exceeds the supported length");
    }
    if (comma == std::string_view::npos) break;
    start = comma + 1;
  }
  return domains;
}

Expected<Evidence<std::uint64_t>> ParseEvidenceU64(const std::string& token) {
  if (token == kUnknown) return Evidence<std::uint64_t>::Unknown();
  if (token == kConflicting) return Evidence<std::uint64_t>::Conflicting();
  auto value = ParseU64(token);
  if (!value.ok()) return value.status();
  return Evidence<std::uint64_t>::Known(value.value());
}

Expected<Evidence<std::uint32_t>> ParseEvidenceU32(const std::string& token) {
  if (token == kUnknown) return Evidence<std::uint32_t>::Unknown();
  if (token == kConflicting) return Evidence<std::uint32_t>::Conflicting();
  auto value = ParseU32(token);
  if (!value.ok()) return value.status();
  return Evidence<std::uint32_t>::Known(value.value());
}

Expected<Evidence<double>> ParseEvidenceDouble(const std::string& token) {
  if (token == kUnknown) return Evidence<double>::Unknown();
  if (token == kConflicting) return Evidence<double>::Conflicting();
  auto value = ParseDouble(token);
  if (!value.ok()) return value.status();
  return Evidence<double>::Known(value.value());
}

Expected<Evidence<SlotMask>> ParseEvidenceMask(const std::string& token) {
  if (token == kUnknown) return Evidence<SlotMask>::Unknown();
  if (token == kConflicting) return Evidence<SlotMask>::Conflicting();
  auto value = SlotMask::FromHex(token);
  if (!value.ok()) return value.status();
  return Evidence<SlotMask>::Known(value.value());
}

Expected<Evidence<AdminState>> ParseEvidenceAdmin(const std::string& token) {
  if (token == kUnknown) return Evidence<AdminState>::Unknown();
  if (token == kConflicting) return Evidence<AdminState>::Conflicting();
  AdminState state = AdminState::Up;
  if (!ParseAdminState(token, &state)) {
    return Failure(StatusCode::MalformedInput, "administrative state token '" + token + "' is not recognised");
  }
  return Evidence<AdminState>::Known(state);
}

Expected<Evidence<std::optional<ProfileId>>> ParseEvidenceProfile(const std::string& token) {
  if (token == kUnknown) return Evidence<std::optional<ProfileId>>::Unknown();
  if (token == kConflicting) return Evidence<std::optional<ProfileId>>::Conflicting();
  if (token == kAbsent) return Evidence<std::optional<ProfileId>>::Known(std::nullopt);
  auto id = ProfileId::Parse(token);
  if (!id.ok()) return id.status();
  return Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(std::move(id.value())));
}

void AddDomains(LineAssembler* line, const std::vector<FailureDomainId>& domains) {
  if (!domains.empty()) line->AddKeyRaw("domains", JoinDomains(domains));
}

void AddMask(LineAssembler* line, std::string_view key, const Evidence<SlotMask>& mask) {
  switch (mask.state()) {
    case Knowledge::Known:
      line->AddKeyRaw(key, mask.value().ToHex());
      return;
    case Knowledge::Unknown:
      line->AddKeyRaw(key, kUnknown);
      return;
    case Knowledge::Conflicting:
      line->AddKeyRaw(key, kConflicting);
      return;
  }
}

void AddU64Evidence(LineAssembler* line, std::string_view key, const Evidence<std::uint64_t>& evidence) {
  switch (evidence.state()) {
    case Knowledge::Known:
      line->AddKeyU64(key, evidence.value());
      return;
    case Knowledge::Unknown:
      line->AddKeyRaw(key, kUnknown);
      return;
    case Knowledge::Conflicting:
      line->AddKeyRaw(key, kConflicting);
      return;
  }
}

void AddU32Evidence(LineAssembler* line, std::string_view key, const Evidence<std::uint32_t>& evidence) {
  switch (evidence.state()) {
    case Knowledge::Known:
      line->AddKeyU64(key, evidence.value());
      return;
    case Knowledge::Unknown:
      line->AddKeyRaw(key, kUnknown);
      return;
    case Knowledge::Conflicting:
      line->AddKeyRaw(key, kConflicting);
      return;
  }
}

void AddDoubleEvidence(LineAssembler* line, std::string_view key, const Evidence<double>& evidence) {
  switch (evidence.state()) {
    case Knowledge::Known:
      line->AddKeyDouble(key, evidence.value());
      return;
    case Knowledge::Unknown:
      line->AddKeyRaw(key, kUnknown);
      return;
    case Knowledge::Conflicting:
      line->AddKeyRaw(key, kConflicting);
      return;
  }
}

void AddAdmin(LineAssembler* line, std::string_view key, const Evidence<AdminState>& admin) {
  switch (admin.state()) {
    case Knowledge::Known:
      line->AddKeyRaw(key, AdminStateName(admin.value()));
      return;
    case Knowledge::Unknown:
      line->AddKeyRaw(key, kUnknown);
      return;
    case Knowledge::Conflicting:
      line->AddKeyRaw(key, kConflicting);
      return;
  }
}

void AddProfileEvidence(LineAssembler* line, std::string_view key,
                        const Evidence<std::optional<ProfileId>>& evidence) {
  switch (evidence.state()) {
    case Knowledge::Known:
      if (evidence.value().has_value()) {
        line->AddKeyRaw(key, evidence.value().value().str());
      } else {
        line->AddKeyRaw(key, kAbsent);
      }
      return;
    case Knowledge::Unknown:
      line->AddKeyRaw(key, kUnknown);
      return;
    case Knowledge::Conflicting:
      line->AddKeyRaw(key, kConflicting);
      return;
  }
}

template <class T>
Expected<T> Required(const std::vector<std::string>& tokens, std::size_t index, const char* what) {
  if (index >= tokens.size()) {
    return Failure(StatusCode::MalformedInput, std::string("record is missing the ") + what + " field");
  }
  return T(tokens[index]);
}

Expected<std::string> RequiredKey(const std::vector<std::string>& tokens, std::size_t first, const char* key) {
  auto raw = FindKeyedField(tokens, first, key);
  if (raw.ok()) return raw;
  if (raw.status().code == StatusCode::NotFound) {
    return Failure(StatusCode::MalformedInput, std::string("record is missing the '") + key + "' field");
  }
  return raw.status();
}

}  // namespace

std::string SnapshotToText(const TopologySnapshot& snapshot) {
  std::string out;
  out.reserve(4096);
  out += kSnapshotMagic;
  out += " ";
  out += FormatU32(kSnapshotFormatVersion);
  out += "\n";
  {
    LineAssembler line("id");
    line.Add(snapshot.id().str());
    out += line.text();
    out += "\n";
  }
  {
    LineAssembler line("generation");
    line.AddU64(snapshot.generation());
    out += line.text();
    out += "\n";
  }
  {
    LineAssembler line("grid");
    line.Add(GridKindName(snapshot.spectrum().grid));
    out += line.text();
    out += "\n";
  }
  {
    LineAssembler line("slots");
    line.AddU16(snapshot.spectrum().slot_count);
    out += line.text();
    out += "\n";
  }
  for (const SourceRecord& source : snapshot.sources()) {
    LineAssembler line("source");
    line.Add(source.id.str());
    line.AddU64(source.generation);
    line.Add(CoverageName(source.coverage));
    out += line.text();
    out += "\n";
  }
  for (const ReachProfile& profile : snapshot.reach_profiles()) {
    LineAssembler line("profile");
    line.Add(profile.id.str());
    AddU64Evidence(&line, "dist", profile.max_distance_m);
    AddU32Evidence(&line, "spans", profile.max_span_count);
    AddDoubleEvidence(&line, "loss", profile.max_loss_db);
    AddDoubleEvidence(&line, "osnr", profile.min_osnr_db);
    line.AddKeyRaw("src", profile.source.str());
    line.AddKeyU64("gen", profile.generation);
    out += line.text();
    out += "\n";
  }
  for (const NodeRecord& node : snapshot.nodes()) {
    LineAssembler line("node");
    line.Add(node.id.str());
    line.Add(NodeKindName(node.kind));
    line.Add(CoverageName(node.coverage));
    AddAdmin(&line, "admin", node.admin);
    line.AddKeyU64("cost", node.transit_cost);
    line.AddKeyRaw("src", node.source.str());
    line.AddKeyU64("gen", node.generation);
    AddDomains(&line, node.failure_domains);
    out += line.text();
    out += "\n";
  }
  for (const PortRecord& port : snapshot.ports()) {
    LineAssembler line("port");
    line.Add(port.key.node.str());
    line.Add(port.key.port.str());
    line.Add(PortRoleName(port.role));
    AddAdmin(&line, "admin", port.admin);
    AddProfileEvidence(&line, "tx", port.transmit_profile);
    AddMask(&line, "slots", port.blocked_slots);
    line.AddKeyU64("cost", port.transit_cost);
    line.AddKeyRaw("src", port.source.str());
    line.AddKeyU64("gen", port.generation);
    AddDomains(&line, port.failure_domains);
    out += line.text();
    out += "\n";
  }
  for (const SpanRecord& span : snapshot.spans()) {
    LineAssembler line("span");
    line.Add(span.id.str());
    line.Add(span.from.node.str());
    line.Add(span.from.port.str());
    line.Add(span.to.node.str());
    line.Add(span.to.port.str());
    line.Add(span.bidirectional ? "bidir" : "single");
    AddU64Evidence(&line, "len", span.length_m);
    AddDoubleEvidence(&line, "loss", span.loss_db);
    AddDoubleEvidence(&line, "osnr", span.osnr_db);
    AddMask(&line, "slots", span.blocked_slots);
    AddAdmin(&line, "admin", span.admin);
    line.AddKeyU64("cost", span.cost);
    line.AddKeyRaw("src", span.source.str());
    line.AddKeyU64("gen", span.generation);
    AddDomains(&line, span.failure_domains);
    out += line.text();
    out += "\n";
  }
  for (const CrossConnectRecord& cross_connect : snapshot.cross_connects()) {
    LineAssembler line("xc");
    line.Add(cross_connect.id.str());
    line.Add(cross_connect.from.node.str());
    line.Add(cross_connect.from.port.str());
    line.Add(cross_connect.to.node.str());
    line.Add(cross_connect.to.port.str());
    line.Add(CrossConnectOpName(cross_connect.op));
    AddMask(&line, "slots", cross_connect.blocked_slots);
    AddAdmin(&line, "admin", cross_connect.admin);
    line.AddKeyU64("cost", cross_connect.cost);
    line.AddKeyRaw("src", cross_connect.source.str());
    line.AddKeyU64("gen", cross_connect.generation);
    AddDomains(&line, cross_connect.failure_domains);
    out += line.text();
    out += "\n";
  }
  return out;
}

Digest256 ComputeSnapshotDigest(const TopologySnapshot& snapshot) {
  Sha256 hasher;
  hasher.Update(kSnapshotDigestDomain);
  hasher.Update("\n");
  const std::string text = SnapshotToText(snapshot);
  hasher.Update(text);
  return hasher.Finalize();
}

Digest256 SourceContributionDigest(const TopologySnapshot& snapshot, const SourceId& source) {
  Sha256 hasher;
  hasher.Update("OPP-SOURCE-v1");
  hasher.Update("\n");
  const std::string text = SnapshotToText(snapshot);
  const std::string_view view(text);
  std::size_t cursor = 0;
  while (cursor < text.size()) {
    const std::size_t newline = text.find('\n', cursor);
    const std::string_view line =
        newline == std::string_view::npos ? view.substr(cursor) : view.substr(cursor, newline - cursor);
    cursor = newline == std::string_view::npos ? text.size() : newline + 1;
    if (line.empty()) continue;
    const auto tokens = SplitTokens(line);
    if (!tokens.ok()) continue;
    const std::vector<std::string>& values = tokens.value();
    bool belongs = false;
    if (values[0] == "source") {
      belongs = values.size() > 1 && values[1] == source.str();
    } else {
      const auto field = FindKeyedField(values, 1, "src");
      belongs = field.ok() && field.value() == source.str();
    }
    if (!belongs) continue;
    hasher.Update(line);
    hasher.Update("\n");
  }
  return hasher.Finalize();
}

Expected<TopologySnapshot> ParseSnapshotText(std::string_view text) {
  if (text.size() > kMaxSnapshotTextBytes) {
    return Failure(StatusCode::LimitExceeded, "snapshot text exceeds the permitted maximum size");
  }

  std::vector<std::vector<std::string>> records;
  records.reserve(256);

  bool header_seen = false;
  bool have_id = false;
  bool have_generation = false;
  bool have_grid = false;
  bool have_slots = false;
  SnapshotId snapshot_id;
  Generation generation = 0;
  SpectrumModel spectrum;

  std::size_t cursor = 0;
  std::size_t line_number = 0;
  while (cursor <= text.size()) {
    if (cursor == text.size()) break;
    const std::size_t newline = text.find('\n', cursor);
    std::string_view line = newline == std::string_view::npos ? text.substr(cursor) : text.substr(cursor, newline - cursor);
    cursor = newline == std::string_view::npos ? text.size() : newline + 1;
    ++line_number;
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.empty()) continue;

    auto tokens = SplitTokens(line);
    if (!tokens.ok()) {
      return Failure(tokens.status().code,
                     "line " + std::to_string(line_number) + ": " + tokens.status().detail);
    }
    const std::vector<std::string>& values = tokens.value();

    if (!header_seen) {
      if (values.size() != 2 || values[0] != kSnapshotMagic) {
        return Failure(StatusCode::MalformedInput, "snapshot must start with the OPP-SNAPSHOT magic line");
      }
      auto version = ParseU32(values[1]);
      if (!version.ok()) return version.status();
      if (version.value() != kSnapshotFormatVersion) {
        return Failure(StatusCode::Unsupported,
                       "snapshot format revision " + values[1] + " is not supported by this runtime");
      }
      header_seen = true;
      continue;
    }

    const std::string& keyword = values[0];
    if (keyword == "id") {
      if (values.size() != 2) return Failure(StatusCode::MalformedInput, "id record takes exactly one argument");
      if (have_id) return Failure(StatusCode::MalformedInput, "snapshot id is declared more than once");
      auto id = SnapshotId::Parse(values[1]);
      if (!id.ok()) return id.status();
      snapshot_id = std::move(id.value());
      have_id = true;
      continue;
    }
    if (keyword == "generation") {
      if (values.size() != 2) {
        return Failure(StatusCode::MalformedInput, "generation record takes exactly one argument");
      }
      if (have_generation) return Failure(StatusCode::MalformedInput, "generation is declared more than once");
      auto value = ParseU64(values[1]);
      if (!value.ok()) return value.status();
      generation = value.value();
      have_generation = true;
      continue;
    }
    if (keyword == "grid") {
      if (values.size() != 2) return Failure(StatusCode::MalformedInput, "grid record takes exactly one argument");
      if (have_grid) return Failure(StatusCode::MalformedInput, "grid is declared more than once");
      GridKind kind = GridKind::Fixed50GHz;
      if (!ParseGridKind(values[1], &kind)) {
        return Failure(StatusCode::Unsupported, "grid '" + values[1] + "' is not modelled by this runtime");
      }
      spectrum.grid = kind;
      have_grid = true;
      continue;
    }
    if (keyword == "slots") {
      if (values.size() != 2) return Failure(StatusCode::MalformedInput, "slots record takes exactly one argument");
      if (have_slots) return Failure(StatusCode::MalformedInput, "slot count is declared more than once");
      auto value = ParseU16(values[1]);
      if (!value.ok()) return value.status();
      spectrum.slot_count = value.value();
      have_slots = true;
      continue;
    }
    if (keyword == "source" || keyword == "profile" || keyword == "node" || keyword == "port" || keyword == "span" ||
        keyword == "xc") {
      records.push_back(values);
      if (records.size() > static_cast<std::size_t>(kMaxNodes) + kMaxPorts + kMaxSpans + kMaxCrossConnects +
                              kMaxReachProfiles + kMaxSources) {
        return Failure(StatusCode::LimitExceeded, "snapshot declares more records than the supported maximum");
      }
      continue;
    }
    return Failure(StatusCode::MalformedInput, "line " + std::to_string(line_number) + ": unknown record '" + keyword + "'");
  }

  if (!header_seen) return Failure(StatusCode::MalformedInput, "snapshot is empty");
  if (!have_id) return Failure(StatusCode::MalformedInput, "snapshot id is missing");
  if (!have_grid) return Failure(StatusCode::MalformedInput, "spectrum grid is missing");
  if (!have_slots) return Failure(StatusCode::MalformedInput, "spectrum slot count is missing");

  SnapshotBuilder builder;
  builder.SetId(std::move(snapshot_id));
  builder.SetGeneration(generation);
  builder.SetSpectrum(spectrum);

  std::size_t record_number = 0;
  for (const std::vector<std::string>& values : records) {
    ++record_number;
    const std::string& keyword = values[0];
    const auto fail = [&](const Status& status) -> Expected<TopologySnapshot> {
      const Status normalised = NormaliseDecodeStatus(status);
      return Failure(normalised.code, "record " + std::to_string(record_number) + ": " + normalised.detail);
    };

    if (keyword == "source") {
      if (values.size() != 4) return fail(Failure(StatusCode::MalformedInput, "source takes id, generation, coverage"));
      auto id = SourceId::Parse(values[1]);
      if (!id.ok()) return fail(id.status());
      auto gen = ParseU64(values[2]);
      if (!gen.ok()) return fail(gen.status());
      Coverage coverage = Coverage::Complete;
      if (values[3] == "partial") {
        coverage = Coverage::Partial;
      } else if (values[3] != "complete") {
        return fail(Failure(StatusCode::MalformedInput, "source coverage must be complete or partial"));
      }
      SourceRecord record;
      record.id = std::move(id.value());
      record.generation = gen.value();
      record.coverage = coverage;
      const Status status = builder.AddSource(std::move(record));
      if (status.failed()) return fail(status);
      continue;
    }

    if (keyword == "profile") {
      if (values.size() < 2) return fail(Failure(StatusCode::MalformedInput, "profile takes an identifier"));
      auto id = ProfileId::Parse(values[1]);
      if (!id.ok()) return fail(id.status());
      ReachProfile record;
      record.id = std::move(id.value());
      auto dist = RequiredKey(values, 2, "dist");
      if (!dist.ok()) return fail(dist.status());
      auto dist_value = ParseEvidenceU64(dist.value());
      if (!dist_value.ok()) return fail(dist_value.status());
      record.max_distance_m = dist_value.value();
      auto spans = RequiredKey(values, 2, "spans");
      if (!spans.ok()) return fail(spans.status());
      auto spans_value = ParseEvidenceU32(spans.value());
      if (!spans_value.ok()) return fail(spans_value.status());
      record.max_span_count = spans_value.value();
      auto loss = RequiredKey(values, 2, "loss");
      if (!loss.ok()) return fail(loss.status());
      auto loss_value = ParseEvidenceDouble(loss.value());
      if (!loss_value.ok()) return fail(loss_value.status());
      record.max_loss_db = loss_value.value();
      auto osnr = RequiredKey(values, 2, "osnr");
      if (!osnr.ok()) return fail(osnr.status());
      auto osnr_value = ParseEvidenceDouble(osnr.value());
      if (!osnr_value.ok()) return fail(osnr_value.status());
      record.min_osnr_db = osnr_value.value();
      auto src = RequiredKey(values, 2, "src");
      if (!src.ok()) return fail(src.status());
      auto src_id = SourceId::Parse(src.value());
      if (!src_id.ok()) return fail(src_id.status());
      record.source = std::move(src_id.value());
      auto gen = RequiredKey(values, 2, "gen");
      if (!gen.ok()) return fail(gen.status());
      auto gen_value = ParseU64(gen.value());
      if (!gen_value.ok()) return fail(gen_value.status());
      record.generation = gen_value.value();
      const Status status = builder.AddReachProfile(std::move(record));
      if (status.failed()) return fail(status);
      continue;
    }

    if (keyword == "node") {
      if (values.size() < 5) return fail(Failure(StatusCode::MalformedInput, "node takes id, kind, coverage, admin"));
      auto id = NodeId::Parse(values[1]);
      if (!id.ok()) return fail(id.status());
      NodeKind kind = NodeKind::Terminal;
      if (!ParseNodeKind(values[2], &kind)) {
        return fail(Failure(StatusCode::Unsupported, "node kind '" + values[2] + "' is not modelled"));
      }
      NodeRecord record;
      record.id = std::move(id.value());
      record.kind = kind;
      if (values[3] == "partial") {
        record.coverage = Coverage::Partial;
      } else if (values[3] != "complete") {
        return fail(Failure(StatusCode::MalformedInput, "node coverage must be complete or partial"));
      }
      auto admin_text = RequiredKey(values, 4, "admin");
      if (!admin_text.ok()) return fail(admin_text.status());
      auto admin = ParseEvidenceAdmin(admin_text.value());
      if (!admin.ok()) return fail(admin.status());
      record.admin = admin.value();
      auto cost = RequiredKey(values, 5, "cost");
      if (!cost.ok()) return fail(cost.status());
      auto cost_value = ParseU64(cost.value());
      if (!cost_value.ok()) return fail(cost_value.status());
      record.transit_cost = cost_value.value();
      auto src = RequiredKey(values, 5, "src");
      if (!src.ok()) return fail(src.status());
      auto src_id = SourceId::Parse(src.value());
      if (!src_id.ok()) return fail(src_id.status());
      record.source = std::move(src_id.value());
      auto gen = RequiredKey(values, 5, "gen");
      if (!gen.ok()) return fail(gen.status());
      auto gen_value = ParseU64(gen.value());
      if (!gen_value.ok()) return fail(gen_value.status());
      record.generation = gen_value.value();
      const auto domains = FindKeyedField(values, 5, "domains");
      if (domains.ok()) {
        auto parsed = ParseDomains(domains.value());
        if (!parsed.ok()) return fail(parsed.status());
        record.failure_domains = std::move(parsed.value());
      }
      const Status status = builder.AddNode(std::move(record));
      if (status.failed()) return fail(status);
      continue;
    }

    if (keyword == "port") {
      if (values.size() < 4) return fail(Failure(StatusCode::MalformedInput, "port takes node, port, role"));
      auto node = NodeId::Parse(values[1]);
      if (!node.ok()) return fail(node.status());
      auto port = PortId::Parse(values[2]);
      if (!port.ok()) return fail(port.status());
      PortRecord record;
      record.key.node = std::move(node.value());
      record.key.port = std::move(port.value());
      if (!ParsePortRole(values[3], &record.role)) {
        return fail(Failure(StatusCode::MalformedInput, "port role '" + values[3] + "' is not recognised"));
      }
      auto admin = RequiredKey(values, 4, "admin");
      if (!admin.ok()) return fail(admin.status());
      auto admin_value = ParseEvidenceAdmin(admin.value());
      if (!admin_value.ok()) return fail(admin_value.status());
      record.admin = admin_value.value();
      auto tx = RequiredKey(values, 4, "tx");
      if (!tx.ok()) return fail(tx.status());
      auto tx_value = ParseEvidenceProfile(tx.value());
      if (!tx_value.ok()) return fail(tx_value.status());
      record.transmit_profile = tx_value.value();
      auto slots = RequiredKey(values, 4, "slots");
      if (!slots.ok()) return fail(slots.status());
      auto slots_value = ParseEvidenceMask(slots.value());
      if (!slots_value.ok()) return fail(slots_value.status());
      record.blocked_slots = slots_value.value();
      auto cost = RequiredKey(values, 4, "cost");
      if (!cost.ok()) return fail(cost.status());
      auto cost_value = ParseU64(cost.value());
      if (!cost_value.ok()) return fail(cost_value.status());
      record.transit_cost = cost_value.value();
      auto src = RequiredKey(values, 4, "src");
      if (!src.ok()) return fail(src.status());
      auto src_id = SourceId::Parse(src.value());
      if (!src_id.ok()) return fail(src_id.status());
      record.source = std::move(src_id.value());
      auto gen = RequiredKey(values, 4, "gen");
      if (!gen.ok()) return fail(gen.status());
      auto gen_value = ParseU64(gen.value());
      if (!gen_value.ok()) return fail(gen_value.status());
      record.generation = gen_value.value();
      const auto domains = FindKeyedField(values, 4, "domains");
      if (domains.ok()) {
        auto parsed = ParseDomains(domains.value());
        if (!parsed.ok()) return fail(parsed.status());
        record.failure_domains = std::move(parsed.value());
      }
      const Status status = builder.AddPort(std::move(record));
      if (status.failed()) return fail(status);
      continue;
    }

    if (keyword == "span") {
      if (values.size() < 7) {
        return fail(Failure(StatusCode::MalformedInput, "span takes id, two endpoints and a direction"));
      }
      auto id = SpanId::Parse(values[1]);
      if (!id.ok()) return fail(id.status());
      auto from_node = NodeId::Parse(values[2]);
      if (!from_node.ok()) return fail(from_node.status());
      auto from_port = PortId::Parse(values[3]);
      if (!from_port.ok()) return fail(from_port.status());
      auto to_node = NodeId::Parse(values[4]);
      if (!to_node.ok()) return fail(to_node.status());
      auto to_port = PortId::Parse(values[5]);
      if (!to_port.ok()) return fail(to_port.status());
      SpanRecord record;
      record.id = std::move(id.value());
      record.from.node = std::move(from_node.value());
      record.from.port = std::move(from_port.value());
      record.to.node = std::move(to_node.value());
      record.to.port = std::move(to_port.value());
      if (values[6] == "bidir") {
        record.bidirectional = true;
      } else if (values[6] == "single") {
        record.bidirectional = false;
      } else {
        return fail(Failure(StatusCode::MalformedInput, "span direction must be bidir or single"));
      }
      auto len = RequiredKey(values, 7, "len");
      if (!len.ok()) return fail(len.status());
      auto len_value = ParseEvidenceU64(len.value());
      if (!len_value.ok()) return fail(len_value.status());
      record.length_m = len_value.value();
      auto loss = RequiredKey(values, 7, "loss");
      if (!loss.ok()) return fail(loss.status());
      auto loss_value = ParseEvidenceDouble(loss.value());
      if (!loss_value.ok()) return fail(loss_value.status());
      record.loss_db = loss_value.value();
      auto osnr = RequiredKey(values, 7, "osnr");
      if (!osnr.ok()) return fail(osnr.status());
      auto osnr_value = ParseEvidenceDouble(osnr.value());
      if (!osnr_value.ok()) return fail(osnr_value.status());
      record.osnr_db = osnr_value.value();
      auto slots = RequiredKey(values, 7, "slots");
      if (!slots.ok()) return fail(slots.status());
      auto slots_value = ParseEvidenceMask(slots.value());
      if (!slots_value.ok()) return fail(slots_value.status());
      record.blocked_slots = slots_value.value();
      auto admin = RequiredKey(values, 7, "admin");
      if (!admin.ok()) return fail(admin.status());
      auto admin_value = ParseEvidenceAdmin(admin.value());
      if (!admin_value.ok()) return fail(admin_value.status());
      record.admin = admin_value.value();
      auto cost = RequiredKey(values, 7, "cost");
      if (!cost.ok()) return fail(cost.status());
      auto cost_value = ParseU64(cost.value());
      if (!cost_value.ok()) return fail(cost_value.status());
      record.cost = cost_value.value();
      auto src = RequiredKey(values, 7, "src");
      if (!src.ok()) return fail(src.status());
      auto src_id = SourceId::Parse(src.value());
      if (!src_id.ok()) return fail(src_id.status());
      record.source = std::move(src_id.value());
      auto gen = RequiredKey(values, 7, "gen");
      if (!gen.ok()) return fail(gen.status());
      auto gen_value = ParseU64(gen.value());
      if (!gen_value.ok()) return fail(gen_value.status());
      record.generation = gen_value.value();
      const auto domains = FindKeyedField(values, 7, "domains");
      if (domains.ok()) {
        auto parsed = ParseDomains(domains.value());
        if (!parsed.ok()) return fail(parsed.status());
        record.failure_domains = std::move(parsed.value());
      }
      const Status status = builder.AddSpan(std::move(record));
      if (status.failed()) return fail(status);
      continue;
    }

    // keyword == "xc"
    if (values.size() < 7) {
      return fail(Failure(StatusCode::MalformedInput, "xc takes id, two endpoints and an operation"));
    }
    auto id = CrossConnectId::Parse(values[1]);
    if (!id.ok()) return fail(id.status());
    auto from_node = NodeId::Parse(values[2]);
    if (!from_node.ok()) return fail(from_node.status());
    auto from_port = PortId::Parse(values[3]);
    if (!from_port.ok()) return fail(from_port.status());
    auto to_node = NodeId::Parse(values[4]);
    if (!to_node.ok()) return fail(to_node.status());
    auto to_port = PortId::Parse(values[5]);
    if (!to_port.ok()) return fail(to_port.status());
    CrossConnectRecord record;
    record.id = std::move(id.value());
    record.from.node = std::move(from_node.value());
    record.from.port = std::move(from_port.value());
    record.to.node = std::move(to_node.value());
    record.to.port = std::move(to_port.value());
    if (!ParseCrossConnectOp(values[6], &record.op)) {
      return fail(Failure(StatusCode::Unsupported, "cross-connect operation '" + values[6] + "' is not modelled"));
    }
    auto slots = RequiredKey(values, 7, "slots");
    if (!slots.ok()) return fail(slots.status());
    auto slots_value = ParseEvidenceMask(slots.value());
    if (!slots_value.ok()) return fail(slots_value.status());
    record.blocked_slots = slots_value.value();
    auto admin = RequiredKey(values, 7, "admin");
    if (!admin.ok()) return fail(admin.status());
    auto admin_value = ParseEvidenceAdmin(admin.value());
    if (!admin_value.ok()) return fail(admin_value.status());
    record.admin = admin_value.value();
    auto cost = RequiredKey(values, 7, "cost");
    if (!cost.ok()) return fail(cost.status());
    auto cost_value = ParseU64(cost.value());
    if (!cost_value.ok()) return fail(cost_value.status());
    record.cost = cost_value.value();
    auto src = RequiredKey(values, 7, "src");
    if (!src.ok()) return fail(src.status());
    auto src_id = SourceId::Parse(src.value());
    if (!src_id.ok()) return fail(src_id.status());
    record.source = std::move(src_id.value());
    auto gen = RequiredKey(values, 7, "gen");
    if (!gen.ok()) return fail(gen.status());
    auto gen_value = ParseU64(gen.value());
    if (!gen_value.ok()) return fail(gen_value.status());
    record.generation = gen_value.value();
    const auto domains = FindKeyedField(values, 7, "domains");
    if (domains.ok()) {
      auto parsed = ParseDomains(domains.value());
      if (!parsed.ok()) return fail(parsed.status());
      record.failure_domains = std::move(parsed.value());
    }
    const Status status = builder.AddCrossConnect(std::move(record));
    if (status.failed()) return fail(status);
  }

  return builder.Build();
}

Expected<TopologySnapshot> LoadSnapshotFile(const std::string& path) {
  const auto bytes = ReadFileBounded(path, kMaxSnapshotTextBytes);
  if (!bytes.ok()) return bytes.status();
  return ParseSnapshotText(bytes.value());
}

Status SaveSnapshotFile(const std::string& path, const TopologySnapshot& snapshot) {
  return WriteFileAtomic(path, SnapshotToText(snapshot));
}

}  // namespace opp
