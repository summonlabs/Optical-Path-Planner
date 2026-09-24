// Adversarial suite: malformed input, extreme values, duplicate identities,
// bounds, overflow, conflicting evidence, replayed evidence and cancellation.
//
// Nothing in this suite relies on wall-clock timing. Cancellation is driven by
// the search's own observation hook, so it fires at a known expansion boundary.

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "opp/opp.hpp"
#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace opp;
using opp_test::BuildCompleteSnapshot;
using opp_test::BuildPartialCoverageSnapshot;
using opp_test::BuildSnapshotWithUnknownOsnr;
using opp_test::BuildTwoNodeSnapshot;
using opp_test::Random;

PortKey Key(const char* node, const char* port) {
  return PortKey{NodeId::Trusted(node), PortId::Trusted(port)};
}

PlanningRequest BasicRequest() {
  PlanningRequest request;
  request.id = RequestId::Trusted("adversarial");
  request.source = Key("n0", "c0");
  request.destination = Key("n5", "c0");
  return request;
}

}  // namespace

OPP_TEST(adversarial, snapshot_text_mutations_never_crash) {
  const auto built = opp_test::BuildCompleteSnapshot(31, 6, 8, 4);
  OPP_REQUIRE(built.ok());
  const std::string original = SnapshotToText(built.value());

  Random random(0xfeedbeefull);
  std::uint32_t parsed_ok = 0;
  std::uint32_t rejected = 0;
  for (std::uint32_t iteration = 0; iteration < 400; ++iteration) {
    std::string mutated = original;
    const std::uint32_t mutations = 1 + random.Below(3);
    for (std::uint32_t i = 0; i < mutations; ++i) {
      const std::size_t position = random.Below(static_cast<std::uint32_t>(mutated.size()));
      switch (random.Below(4)) {
        case 0:
          mutated[position] = static_cast<char>(random.Below(256));
          break;
        case 1:
          mutated[position] = ' ';
          break;
        case 2:
          mutated.insert(position, "=");
          break;
        default:
          mutated.erase(position, 1);
          break;
      }
      if (mutated.empty()) mutated = "x";
    }
    const auto outcome = ParseSnapshotText(mutated);
    if (outcome.ok()) {
      parsed_ok += 1;
      // A snapshot that parses must re-encode to exactly the bytes it came from,
      // which is what makes its digest meaningful.
      const std::string reencoded = SnapshotToText(outcome.value());
      const auto again = ParseSnapshotText(reencoded);
      OPP_REQUIRE(again.ok());
      OPP_CHECK(again.value().digest() == outcome.value().digest());
      OPP_CHECK_EQ(SnapshotToText(again.value()), reencoded);
    } else {
      rejected += 1;
      OPP_CHECK(outcome.status().code != StatusCode::Ok);
      OPP_CHECK(!outcome.status().detail.empty());
    }
  }
  OPP_CHECK_MSG(rejected > 0, "mutation fuzzing produced no rejection at all");
  OPP_CHECK_MSG(parsed_ok + rejected == 400, "mutation fuzzing lost an iteration");
}

OPP_TEST(adversarial, request_text_mutations_never_crash) {
  PlanningRequest request = BasicRequest();
  request.constraints.excluded_nodes.push_back(NodeId::Trusted("n9"));
  request.required_source_generations[SourceId::Trusted("src")] = 3;
  const std::string original = RequestToText(request);

  Random random(0x1234abcdull);
  for (std::uint32_t iteration = 0; iteration < 300; ++iteration) {
    std::string mutated = original;
    const std::size_t position = random.Below(static_cast<std::uint32_t>(mutated.size()));
    mutated[position] = static_cast<char>(random.Below(256));
    const auto outcome = ParseRequestText(mutated);
    if (outcome.ok()) {
      OPP_CHECK_EQ(RequestToText(outcome.value()), mutated);
    } else {
      OPP_CHECK(!outcome.status().detail.empty());
    }
  }
}

OPP_TEST(adversarial, plan_artifact_mutations_never_crash) {
  const auto built = opp_test::BuildCompleteSnapshot(32, 8, 8, 0);
  OPP_REQUIRE(built.ok());
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), BasicRequest());
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  const std::string original = result.candidates.front().CanonicalBytes();

  Random random(0x0badc0deull);
  std::uint32_t accepted = 0;
  for (std::uint32_t iteration = 0; iteration < 300; ++iteration) {
    std::string mutated = original;
    const std::size_t position = random.Below(static_cast<std::uint32_t>(mutated.size()));
    mutated[position] = static_cast<char>(random.Below(256));
    const auto outcome = ParsePlanArtifact(mutated);
    if (outcome.ok()) {
      accepted += 1;
      OPP_CHECK(outcome.value().VerifySeal().ok());
      // An artifact that parses must denote exactly the same plan: the only
      // mutations that can survive are ones that do not change the parsed
      // content, for example replacing one whitespace character with another.
      OPP_CHECK_MSG(outcome.value().CanonicalBytes() == original,
                    "a mutated artifact parsed into different content without failing its seal");
    } else {
      OPP_CHECK(!outcome.status().detail.empty());
    }
  }
  OPP_CHECK(accepted < 300);
}

OPP_TEST(adversarial, store_file_mutations_never_crash) {
  const auto built = opp_test::BuildCompleteSnapshot(33, 8, 8, 0);
  OPP_REQUIRE(built.ok());
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), BasicRequest());
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  const auto encoded = EncodeStoreFile(result.candidates.front());
  OPP_REQUIRE(encoded.ok());

  Random random(0x55aa55aaull);
  for (std::uint32_t iteration = 0; iteration < 300; ++iteration) {
    std::string mutated = encoded.value();
    const std::size_t position = random.Below(static_cast<std::uint32_t>(mutated.size()));
    mutated[position] = static_cast<char>(random.Below(256));
    const auto outcome = DecodeStoreFile(mutated);
    if (!outcome.ok()) {
      OPP_CHECK(outcome.status().code != StatusCode::Ok);
    } else {
      OPP_CHECK(outcome.value().VerifySeal().ok());
    }
  }
  // Truncations at every length must be rejected.
  for (std::size_t length = 0; length < encoded.value().size(); length += 37) {
    OPP_CHECK(!DecodeStoreFile(encoded.value().substr(0, length)).ok());
  }
}

OPP_TEST(adversarial, protocol_frames_are_bounded_and_checked) {
  Frame frame;
  frame.kind = MessageKind::Stats;
  frame.sequence = 5;
  frame.epoch_pin = 2;
  const std::string encoded = EncodeFrame(frame);
  std::size_t consumed = 0;
  const auto decoded = DecodeFrame(encoded, &consumed);
  OPP_REQUIRE(decoded.ok());
  OPP_CHECK_EQ(consumed, encoded.size());
  OPP_CHECK(decoded.value().kind == MessageKind::Stats);
  OPP_CHECK_EQ(decoded.value().sequence, std::uint64_t{5});
  OPP_CHECK_EQ(decoded.value().epoch_pin, std::uint64_t{2});

  OPP_CHECK(FrameSize(encoded.substr(0, 4)).status().code == StatusCode::NotFound);
  OPP_CHECK(FrameSize(std::string(64, '\0')).status().code == StatusCode::MalformedInput);
  OPP_CHECK(DecodeFrame(encoded.substr(0, encoded.size() - 1), &consumed).ok() == false);

  std::string flipped = encoded;
  flipped[flipped.size() - 1] = static_cast<char>(flipped[flipped.size() - 1] ^ 0xff);
  OPP_CHECK(DecodeFrame(flipped, &consumed).status().code == StatusCode::IntegrityFailure);

  // A declared payload larger than the bound is refused before any allocation.
  Frame huge;
  huge.kind = MessageKind::Plan;
  std::string overflow_header;
  ByteWriter writer;
  writer.U32(kFrameMagic);
  writer.U32(kProtocolVersion);
  writer.U32(static_cast<std::uint32_t>(MessageKind::Plan));
  writer.U64(1);
  writer.U64(0);
  writer.U32(kMaxFrameBytes + 1);
  overflow_header = writer.buffer();
  overflow_header.append(64, '\0');
  OPP_CHECK(FrameSize(overflow_header).status().code == StatusCode::LimitExceeded);

  // Payload codecs reject trailing bytes and short payloads.
  HelloMessage hello;
  hello.client_name = "client";
  const std::string payload = EncodeHello(hello);
  OPP_CHECK(DecodeHello(payload).ok());
  OPP_CHECK(DecodeHello(payload + "x").status().code == StatusCode::MalformedInput);
  OPP_CHECK(DecodeHello(payload.substr(0, payload.size() - 1)).status().code == StatusCode::MalformedInput);
}

OPP_TEST(adversarial, cost_overflow_is_a_cut_not_a_wrap) {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("overflow"));
  builder.SetGeneration(1);
  SpectrumModel spectrum;
  spectrum.slot_count = 4;
  builder.SetSpectrum(spectrum);

  const SourceId source = SourceId::Trusted("overflow-source");
  SourceRecord source_record;
  source_record.id = source;
  source_record.generation = 1;
  OPP_REQUIRE(builder.AddSource(source_record).ok());

  ReachProfile profile;
  profile.id = ProfileId::Trusted("p");
  profile.max_distance_m = Evidence<std::uint64_t>::Known(1000000);
  profile.max_span_count = Evidence<std::uint32_t>::Known(8);
  profile.max_loss_db = Evidence<double>::Known(100.0);
  profile.min_osnr_db = Evidence<double>::Known(1.0);
  profile.source = source;
  profile.generation = 1;
  OPP_REQUIRE(builder.AddReachProfile(profile).ok());

  for (const char* name : {"a", "b"}) {
    NodeRecord node;
    node.id = NodeId::Trusted(name);
    node.kind = NodeKind::ReconfigurableOadm;
    node.transit_cost = std::numeric_limits<std::uint64_t>::max() - 1;
    node.admin = Evidence<AdminState>::Known(AdminState::Up);
    node.source = source;
    node.generation = 1;
    OPP_REQUIRE(builder.AddNode(node).ok());
    for (const char* port : {"in", "out"}) {
      PortRecord record;
      record.key = Key(name, port);
      record.role = PortRole::Client;
      record.transit_cost = std::numeric_limits<std::uint64_t>::max() - 1;
      record.admin = Evidence<AdminState>::Known(AdminState::Up);
      record.transmit_profile = Evidence<std::optional<ProfileId>>::Known(std::optional<ProfileId>(profile.id));
      record.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
      record.source = source;
      record.generation = 1;
      OPP_REQUIRE(builder.AddPort(record).ok());
    }
    CrossConnectRecord cross_connect;
    cross_connect.id = CrossConnectId::Trusted(std::string("x-") + name);
    cross_connect.from = Key(name, "in");
    cross_connect.to = Key(name, "out");
    cross_connect.op = CrossConnectOp::Express;
    cross_connect.cost = std::numeric_limits<std::uint64_t>::max() - 1;
    cross_connect.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
    cross_connect.admin = Evidence<AdminState>::Known(AdminState::Up);
    cross_connect.source = source;
    cross_connect.generation = 1;
    OPP_REQUIRE(builder.AddCrossConnect(cross_connect).ok());
  }

  SpanRecord span;
  span.id = SpanId::Trusted("s");
  span.from = Key("a", "out");
  span.to = Key("b", "in");
  span.length_m = Evidence<std::uint64_t>::Known(1);
  span.loss_db = Evidence<double>::Known(0.1);
  span.osnr_db = Evidence<double>::Known(30.0);
  span.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  span.cost = std::numeric_limits<std::uint64_t>::max() - 1;
  span.admin = Evidence<AdminState>::Known(AdminState::Up);
  span.source = source;
  span.generation = 1;
  OPP_REQUIRE(builder.AddSpan(span).ok());

  const auto built = builder.Build();
  OPP_REQUIRE(built.ok());

  PlanningRequest request = BasicRequest();
  request.source = Key("a", "in");
  request.destination = Key("b", "in");
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  // Every accumulation overflows, so no route can be assembled. The important
  // property is that the planner says so instead of wrapping to a small cost.
  OPP_CHECK_MSG(result.outcome == PlanOutcome::Infeasible,
                std::string("outcome was ") + PlanOutcomeName(result.outcome));
  OPP_CHECK(result.candidates.empty());
  OPP_CHECK(std::any_of(result.cuts.begin(), result.cuts.end(), [](const CutCount& cut) {
    return cut.reason == CutReason::CostLimitExceeded;
  }));
}

OPP_TEST(adversarial, search_bounds_yield_indeterminate_not_infeasible) {
  const auto built = opp_test::BuildCompleteSnapshot(41, 14, 16, 5);
  OPP_REQUIRE(built.ok());
  PlanningRequest request = BasicRequest();
  request.source = Key("n0", "c0");
  request.destination = Key("n13", "c0");
  request.max_search_expansions = 1;
  request.max_search_labels = 4;
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  OPP_CHECK_MSG(result.outcome == PlanOutcome::Indeterminate,
                std::string("outcome was ") + PlanOutcomeName(result.outcome));
  OPP_CHECK((result.limitations & kLimitationSearchTruncated) != 0);
  OPP_CHECK(result.statistics.truncated);
  OPP_CHECK(!result.optimality_proven);

  // The same request with a generous bound proves a route exists.
  PlanningRequest generous = request;
  generous.max_search_expansions = kDefaultSearchExpansions;
  generous.max_search_labels = kDefaultSearchLabels;
  OPP_CHECK(planner.Plan(built.value(), generous).outcome == PlanOutcome::Feasible);
}

OPP_TEST(adversarial, cancellation_is_real_and_publishes_nothing) {
  const auto built = opp_test::BuildCompleteSnapshot(42, 16, 24, 5);
  OPP_REQUIRE(built.ok());
  PlanningRequest request = BasicRequest();
  request.source = Key("n0", "c0");
  request.destination = Key("n15", "c0");
  const Planner planner;

  // A token that is already cancelled short-circuits before any expansion.
  CancelToken pre_cancelled;
  pre_cancelled.Request();
  const PlanningResult refused = planner.Plan(built.value(), request, pre_cancelled);
  OPP_CHECK(refused.outcome == PlanOutcome::Cancelled);
  OPP_CHECK(refused.status.code == StatusCode::Cancelled);
  OPP_CHECK(refused.candidates.empty());
  OPP_CHECK_EQ(refused.statistics.labels_expanded, std::uint64_t{0});

  // A live search is cancelled at a known expansion boundary through the
  // observation hook.
  constexpr std::uint64_t kCancelAfter = 25;
  CancelToken token;
  std::uint64_t observed = 0;
  const SearchObserver observer = [&token, &observed](const PlanningStatistics& statistics) {
    observed = statistics.labels_expanded;
    if (statistics.labels_expanded >= kCancelAfter) token.Request();
  };
  const PlanningResult cancelled = planner.Plan(built.value(), request, token, observer);
  OPP_CHECK_MSG(observed >= kCancelAfter, "the search finished before the cancellation boundary was reached");
  OPP_CHECK(cancelled.outcome == PlanOutcome::Cancelled);
  OPP_CHECK(cancelled.candidates.empty());
  OPP_CHECK(!cancelled.optimality_proven);
  OPP_CHECK(cancelled.status.detail.find("cancel") != std::string::npos);

  // Cancelling a token after a completed search changes nothing about the result
  // that was already sealed.
  CancelToken late;
  const PlanningResult completed = planner.Plan(built.value(), request);
  OPP_REQUIRE(completed.outcome == PlanOutcome::Feasible);
  late.Request();
  const PlanningResult repeated = planner.Plan(built.value(), request, late);
  OPP_CHECK(repeated.outcome == PlanOutcome::Cancelled);
  OPP_CHECK_EQ(completed.CanonicalBytes(), planner.Plan(built.value(), request).CanonicalBytes());
}

OPP_TEST(adversarial, conflicting_evidence_is_indeterminate) {
  const auto built = opp_test::BuildCompleteSnapshot(43, 8, 8, 0);
  OPP_REQUIRE(built.ok());
  const Planner planner;
  const PlanningRequest request = BasicRequest();

  // Rebuild the same snapshot with one duplicated, disagreeing span record. The
  // canonical first record survives, but the identity is marked conflicted and
  // every route through it becomes unprovable.
  const SpanRecord* victim = nullptr;
  for (const SpanRecord& span : built.value().spans()) {
    if (span.from.node == NodeId::Trusted("n0")) {
      victim = &span;
      break;
    }
  }
  OPP_REQUIRE(victim != nullptr);

  SnapshotBuilder builder;
  builder.SetId(built.value().id());
  builder.SetGeneration(built.value().generation());
  builder.SetSpectrum(built.value().spectrum());
  for (const SourceRecord& source : built.value().sources()) OPP_REQUIRE(builder.AddSource(source).ok());
  for (const ReachProfile& profile : built.value().reach_profiles()) OPP_REQUIRE(builder.AddReachProfile(profile).ok());
  for (const NodeRecord& node : built.value().nodes()) OPP_REQUIRE(builder.AddNode(node).ok());
  for (const PortRecord& port : built.value().ports()) OPP_REQUIRE(builder.AddPort(port).ok());
  for (const CrossConnectRecord& cross_connect : built.value().cross_connects()) {
    OPP_REQUIRE(builder.AddCrossConnect(cross_connect).ok());
  }
  for (const SpanRecord& span : built.value().spans()) {
    OPP_REQUIRE(builder.AddSpan(span).ok());
    if (&span == victim) {
      SpanRecord disagreeing = span;
      disagreeing.length_m = Evidence<std::uint64_t>::Known(span.length_m.ValueOr(0) + 12345);
      OPP_REQUIRE(builder.AddSpan(disagreeing).ok());
    }
  }
  const auto conflicting = builder.Build();
  OPP_REQUIRE(conflicting.ok());
  OPP_CHECK(!conflicting.value().coverage_complete());
  OPP_CHECK(!conflicting.value().conflicted_resources().empty());

  const PlanningResult result = planner.Plan(conflicting.value(), request);
  // Whether the conflicted span lies on the optimum or not, the planner must
  // never claim FEASIBLE from a snapshot that contains a contradiction it used.
  if (result.outcome == PlanOutcome::Feasible) {
    for (const PlanStep& step : result.candidates.front().steps) {
      OPP_CHECK(!conflicting.value().IsConflicted(step.resource));
    }
  } else {
    OPP_CHECK(result.outcome == PlanOutcome::Indeterminate);
  }
}

OPP_TEST(adversarial, replayed_plan_is_rejected_after_a_generation_bump) {
  SyntheticOptions options;
  options.seed = 44;
  options.node_count = 8;
  options.degree = 3;
  options.slot_count = 8;
  options.generation = 10;
  const auto first = GenerateSyntheticTopology(options);
  OPP_REQUIRE(first.ok());
  const Planner planner;
  const PlanningResult result = planner.Plan(first.value(), BasicRequest());
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  const PlanArtifact plan = result.candidates.front();
  OPP_CHECK(ValidatePlanBindings(plan, first.value()).validity == PlanValidity::Valid);

  options.generation = 11;
  const auto second = GenerateSyntheticTopology(options);
  OPP_REQUIRE(second.ok());
  // The topology shape is identical; only the published generation moved.
  OPP_CHECK(second.value().ArcCount() == first.value().ArcCount());
  const ValidationReport replayed = ValidatePlanBindings(plan, second.value());
  OPP_CHECK_MSG(replayed.validity == PlanValidity::Stale, "a replayed plan was accepted after a generation bump");

  // Re-planning against the new generation yields a plan bound to the new one.
  const PlanningResult replanned = planner.Plan(second.value(), BasicRequest());
  OPP_REQUIRE(replanned.outcome == PlanOutcome::Feasible);
  OPP_CHECK(ValidatePlanBindings(replanned.candidates.front(), second.value()).validity == PlanValidity::Valid);
  OPP_CHECK(ValidatePlanBindings(replanned.candidates.front(), first.value()).validity == PlanValidity::Stale);
}

OPP_TEST(adversarial, bounded_snapshot_counts_are_refused) {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("oversized"));
  SpectrumModel spectrum;
  spectrum.slot_count = 4;
  builder.SetSpectrum(spectrum);
  NodeRecord node;
  node.id = NodeId::Trusted("n");
  node.admin = Evidence<AdminState>::Known(AdminState::Up);
  for (std::uint32_t i = 0; i < kMaxNodes; ++i) {
    OPP_REQUIRE(builder.AddNode(node).ok());
  }
  OPP_CHECK(builder.AddNode(node).code == StatusCode::LimitExceeded);

  SnapshotBuilder port_builder;
  port_builder.SetId(SnapshotId::Trusted("oversized-ports"));
  port_builder.SetSpectrum(spectrum);
  PortRecord port;
  port.key = Key("n", "p");
  port.admin = Evidence<AdminState>::Known(AdminState::Up);
  port.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  for (std::uint32_t i = 0; i < kMaxPorts; ++i) {
    OPP_REQUIRE(port_builder.AddPort(port).ok());
  }
  OPP_CHECK(port_builder.AddPort(port).code == StatusCode::LimitExceeded);

  // Too many failure domains on one resource is refused at build time.
  SnapshotBuilder domain_builder;
  domain_builder.SetId(SnapshotId::Trusted("domains"));
  domain_builder.SetSpectrum(spectrum);
  NodeRecord crowded;
  crowded.id = NodeId::Trusted("crowded");
  crowded.admin = Evidence<AdminState>::Known(AdminState::Up);
  for (std::uint32_t i = 0; i < kMaxDomainsPerResource + 1; ++i) {
    crowded.failure_domains.push_back(FailureDomainId::Trusted("d" + std::to_string(i)));
  }
  OPP_REQUIRE(domain_builder.AddNode(crowded).ok());
  OPP_CHECK(domain_builder.Build().status().code == StatusCode::LimitExceeded);
}

OPP_TEST(adversarial, domain_member_limits_are_enforced) {
  const auto built = opp_test::BuildCompleteSnapshot(45, 8, 8, 0);
  OPP_REQUIRE(built.ok());
  const Planner planner;
  PlanningRequest request = BasicRequest();

  // Count the members the unconstrained best route exposes.
  const PlanningResult unrestricted = planner.Plan(built.value(), request);
  OPP_REQUIRE(unrestricted.outcome == PlanOutcome::Feasible);
  for (const FailureDomainExposure& exposure : unrestricted.candidates.front().failure_domain_exposure) {
    PlanningRequest limited = request;
    limited.constraints.max_members_per_failure_domain[exposure.id] = 1;
    const PlanningResult result = planner.Plan(built.value(), limited);
    OPP_CHECK_MSG(result.outcome == PlanOutcome::Feasible || result.outcome == PlanOutcome::Infeasible,
                  std::string(PlanOutcomeName(result.outcome)) + " " + result.status.detail + " truncated=" +
                      (result.statistics.truncated ? "true" : "false") + " labels=" +
                      std::to_string(result.statistics.labels_created) + " domain=" + exposure.id.str() +
                      " limit=1");
    if (result.outcome == PlanOutcome::Feasible) {
      for (const FailureDomainExposure& candidate_exposure :
           result.candidates.front().failure_domain_exposure) {
        const auto limit = limited.constraints.max_members_per_failure_domain.find(candidate_exposure.id);
        if (limit == limited.constraints.max_members_per_failure_domain.end()) continue;
        OPP_CHECK_MSG(candidate_exposure.member_count <= limit->second,
                      "a candidate exceeded a declared failure-domain member limit");
      }
    }
  }
}

OPP_TEST(adversarial, extreme_thresholds_do_not_change_the_verdict_class) {
  const auto built = opp_test::BuildCompleteSnapshot(46, 10, 8, 0);
  OPP_REQUIRE(built.ok());
  const Planner planner;

  PlanningRequest max_distance = BasicRequest();
  max_distance.constraints.max_total_distance_m = std::numeric_limits<std::uint64_t>::max();
  OPP_CHECK(planner.Plan(built.value(), max_distance).outcome == PlanOutcome::Feasible);

  PlanningRequest max_cost = BasicRequest();
  max_cost.max_total_cost = std::numeric_limits<std::uint64_t>::max();
  OPP_CHECK(planner.Plan(built.value(), max_cost).outcome == PlanOutcome::Feasible);

  PlanningRequest zero_budget = BasicRequest();
  zero_budget.max_total_cost = 0;
  const PlanningResult result = planner.Plan(built.value(), zero_budget);
  OPP_CHECK(result.outcome == PlanOutcome::Infeasible || result.outcome == PlanOutcome::Indeterminate);

  PlanningRequest huge_osnr = BasicRequest();
  huge_osnr.constraints.min_segment_osnr_db = 1.0e6;
  const PlanningResult osnr_result = planner.Plan(built.value(), huge_osnr);
  OPP_CHECK_MSG(osnr_result.outcome == PlanOutcome::Infeasible,
                std::string(PlanOutcomeName(osnr_result.outcome)) + " " + osnr_result.status.detail);

  PlanningRequest zero_regenerations = BasicRequest();
  zero_regenerations.max_regenerations = 0;
  const PlanningResult no_regen = planner.Plan(built.value(), zero_regenerations);
  OPP_CHECK(no_regen.outcome != PlanOutcome::Refused);
  if (no_regen.outcome == PlanOutcome::Feasible) {
    OPP_CHECK_EQ(no_regen.candidates.front().regenerations, std::uint32_t{0});
  }

  PlanningRequest no_ops = BasicRequest();
  no_ops.constraints.allow_regeneration = false;
  no_ops.constraints.allow_wavelength_conversion = false;
  const PlanningResult conservative = planner.Plan(built.value(), no_ops);
  OPP_CHECK(conservative.outcome == PlanOutcome::Feasible ||
            conservative.outcome == PlanOutcome::Infeasible);
}

OPP_TEST(adversarial, duplicate_identities_in_exclusions_are_refused) {
  PlanningRequest request = BasicRequest();
  request.constraints.excluded_spans.push_back(SpanId::Trusted("a"));
  request.constraints.excluded_spans.push_back(SpanId::Trusted("a"));
  OPP_CHECK(request.Validate().code == StatusCode::DuplicateIdentity);

  PlanningRequest ports = BasicRequest();
  ports.constraints.excluded_ports.push_back(Key("a", "b"));
  ports.constraints.excluded_ports.push_back(Key("a", "b"));
  OPP_CHECK(ports.Validate().code == StatusCode::DuplicateIdentity);

  PlanningRequest zero_limit = BasicRequest();
  zero_limit.constraints.max_members_per_failure_domain[FailureDomainId::Trusted("d")] = 0;
  OPP_CHECK(zero_limit.Validate().code == StatusCode::InvalidArgument);

  PlanningRequest negative_quality = BasicRequest();
  negative_quality.constraints.max_total_loss_db = -1.0;
  OPP_CHECK(negative_quality.Validate().code == StatusCode::InvalidArgument);
}
