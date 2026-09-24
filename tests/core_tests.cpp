// Core suite: identities, canonical codecs, spectrum rules, snapshot ingestion,
// request validation, planning outcomes, plan/result sealing, the store and plan
// validation against current evidence.

#include <algorithm>
#include <cmath>
#include <cstdint>
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

PortKey Key(const char* node, const char* port) {
  return PortKey{NodeId::Trusted(node), PortId::Trusted(port)};
}

PlanningRequest BasicRequest() {
  PlanningRequest request;
  request.id = RequestId::Trusted("core");
  request.source = Key("n0", "c0");
  request.destination = Key("n5", "c0");
  return request;
}

}  // namespace

OPP_TEST(ids, text_validation) {
  OPP_CHECK(IsValidIdText("abc"));
  OPP_CHECK(IsValidIdText("a"));
  OPP_CHECK(IsValidIdText("node-1.2:3/4@5+6_7"));
  OPP_CHECK(!IsValidIdText(""));
  OPP_CHECK(!IsValidIdText("-leading"));
  OPP_CHECK(!IsValidIdText("has space"));
  OPP_CHECK(!IsValidIdText(std::string(kMaxIdLength + 1, 'a')));
  OPP_CHECK(IsValidIdText(std::string(kMaxIdLength, 'a')));

  const auto parsed = NodeId::Parse("n1");
  OPP_REQUIRE(parsed.ok());
  OPP_CHECK_EQ(parsed.value().str(), std::string("n1"));
  OPP_CHECK(NodeId::Parse("").status().code == StatusCode::InvalidArgument);
  OPP_CHECK(NodeId::Trusted("x") == NodeId::Trusted("x"));
  OPP_CHECK(NodeId::Trusted("x") < NodeId::Trusted("y"));
}

OPP_TEST(ids, digest_and_incarnation_hex) {
  Digest256 digest;
  digest.bytes[0] = 0x00;
  digest.bytes[31] = 0xff;
  const std::string hex = digest.ToHex();
  OPP_CHECK_EQ(hex.size(), std::size_t{64});
  const auto parsed = Digest256::FromHex(hex);
  OPP_REQUIRE(parsed.ok());
  OPP_CHECK(parsed.value() == digest);
  OPP_CHECK(Digest256::FromHex("00").status().code == StatusCode::MalformedInput);
  OPP_CHECK(Digest256::FromHex(std::string(64, 'z')).status().code == StatusCode::MalformedInput);
  OPP_CHECK(Digest256{}.IsZero());

  IncarnationId incarnation;
  incarnation.bytes[3] = 0x5a;
  const auto incarnation_round_trip = IncarnationId::FromHex(incarnation.ToHex());
  OPP_REQUIRE(incarnation_round_trip.ok());
  OPP_CHECK(incarnation_round_trip.value() == incarnation);
  OPP_CHECK(IncarnationId{}.IsZero());
}

OPP_TEST(ids, resource_keys) {
  const ResourceKey node = ResourceKey::ForNode(NodeId::Trusted("n1"));
  OPP_CHECK_EQ(ResourceKeyToString(node), std::string("node:n1"));
  const auto parsed = ResourceKeyFromString("node:n1");
  OPP_REQUIRE(parsed.ok());
  OPP_CHECK(parsed.value() == node);

  OPP_CHECK_EQ(ResourceKeyToString(ResourceKey::ForPort(Key("a", "in"))), std::string("port:a:in"));
  OPP_CHECK_EQ(ResourceKeyToString(ResourceKey::ForSpan(SpanId::Trusted("s"))), std::string("span:s"));
  OPP_CHECK_EQ(ResourceKeyToString(ResourceKey::ForCrossConnect(CrossConnectId::Trusted("x"))),
               std::string("crossconnect:x"));
  OPP_CHECK_EQ(ResourceKeyToString(ResourceKey::ForFailureDomain(FailureDomainId::Trusted("d"))),
               std::string("domain:d"));
  OPP_CHECK_EQ(ResourceKeyToString(ResourceKey::ForReachProfile(ProfileId::Trusted("p"))),
               std::string("profile:p"));
  OPP_CHECK_EQ(ResourceKeyToString(ResourceKey::ForChannel(3, 2)), std::string("channel:3+2"));
  OPP_CHECK_EQ(ResourceKeyToString(ResourceKey::ForSource(SourceId::Trusted("src"))), std::string("source:src"));

  OPP_CHECK(ResourceKeyFromString("nocolon").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ResourceKeyFromString("node:").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ResourceKeyFromString("bogus:x").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ResourceKey::ForNode(NodeId::Trusted("a")) < ResourceKey::ForNode(NodeId::Trusted("b")));
  OPP_CHECK(ResourceKey::ForNode(NodeId::Trusted("z")) < ResourceKey::ForPort(Key("a", "a")));
}

OPP_TEST(evidence, tri_state) {
  const Evidence<double> known = Evidence<double>::Known(1.5);
  const Evidence<double> unknown = Evidence<double>::Unknown();
  const Evidence<double> conflicting = Evidence<double>::Conflicting();
  OPP_CHECK(known.HasValue());
  OPP_CHECK_EQ(known.value(), 1.5);
  OPP_CHECK(!unknown.HasValue());
  OPP_CHECK(unknown.IsUnknown());
  OPP_CHECK(conflicting.IsConflicting());
  OPP_CHECK(!conflicting.HasValue());
  // The fallback never masquerades as a published value.
  OPP_CHECK_EQ(unknown.ValueOr(-1.0), -1.0);
  OPP_CHECK_EQ(known.ValueOr(-1.0), 1.5);
  OPP_CHECK(Evidence<double>::Unknown() == Evidence<double>::Unknown());
  OPP_CHECK(!(Evidence<double>::Unknown() == Evidence<double>::Conflicting()));
  OPP_CHECK(Evidence<double>::Conflicting() == Evidence<double>::Conflicting());
  OPP_CHECK(Evidence<double>::Known(2.0) == Evidence<double>::Known(2.0));
  OPP_CHECK(!(Evidence<double>::Known(2.0) == Evidence<double>::Known(3.0)));
  OPP_CHECK_EQ(std::string(KnowledgeName(Knowledge::Conflicting)), std::string("conflicting"));
}

OPP_TEST(canonical, token_round_trip) {
  const char* const samples[] = {"plain", "with space", "with\ttab", "", "unicode-\xc3\xa9",
                                 "percent%20", "%", "a/b:c@d+e*f=g-h_i.j", "\x01\x02"};
  for (const char* sample : samples) {
    const std::string encoded = EncodeToken(sample);
    OPP_CHECK_MSG(IsSafeToken(encoded), "encoded token is not safe: " + encoded);
    const auto decoded = DecodeToken(encoded);
    OPP_REQUIRE(decoded.ok());
    OPP_CHECK_MSG(decoded.value() == sample, "token round trip changed the value");
    OPP_CHECK_EQ(EncodeToken(decoded.value()), encoded);
  }
  OPP_CHECK_EQ(EncodeToken(""), std::string("%"));
  OPP_CHECK(DecodeToken("%").value().empty());
  OPP_CHECK(DecodeToken("%2").status().code == StatusCode::MalformedInput);
  OPP_CHECK(DecodeToken("%zz").status().code == StatusCode::MalformedInput);
  OPP_CHECK(!IsSafeToken(""));
}

OPP_TEST(canonical, numbers) {
  const double values[] = {0.0, -0.0, 1.5, -12.25, 1e-9, 1e12, 0.1, 1.0 / 3.0};
  for (double value : values) {
    const auto text = FormatDouble(value);
    OPP_REQUIRE(text.ok());
    const auto parsed = ParseDouble(text.value());
    OPP_REQUIRE(parsed.ok());
    OPP_CHECK(parsed.value() == value);
  }
  OPP_CHECK(FormatDouble(0.0).value() == "0");
  OPP_CHECK(FormatDouble(NAN).status().code == StatusCode::InvalidArgument);
  OPP_CHECK(FormatDouble(INFINITY).status().code == StatusCode::InvalidArgument);
  OPP_CHECK(ParseDouble("nan").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParseDouble("1e999").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParseDouble("1.2.3").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParseDouble("").status().code == StatusCode::MalformedInput);

  OPP_CHECK_EQ(ParseU64("18446744073709551615").value(), UINT64_MAX);
  OPP_CHECK(ParseU64("18446744073709551616").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParseU64("-1").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParseU64("+1").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParseU32("4294967296").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParseU16("65536").status().code == StatusCode::MalformedInput);
  OPP_CHECK_EQ(ParseBoolToken("true").value(), true);
  OPP_CHECK_EQ(ParseBoolToken("0").value(), false);
  OPP_CHECK(ParseBoolToken("yes").status().code == StatusCode::MalformedInput);
}

OPP_TEST(canonical, checked_arithmetic) {
  std::uint64_t out = 0;
  OPP_CHECK(AddCheckedU64(1, 2, &out));
  OPP_CHECK_EQ(out, std::uint64_t{3});
  OPP_CHECK(!AddCheckedU64(UINT64_MAX, 1, &out));
  OPP_CHECK(!AddCheckedU64(UINT64_MAX, UINT64_MAX, &out));
  OPP_CHECK(AddCheckedU64(UINT64_MAX, 0, &out));
  OPP_CHECK_EQ(out, UINT64_MAX);
  OPP_CHECK(MulCheckedU64(6, 7, &out));
  OPP_CHECK_EQ(out, std::uint64_t{42});
  OPP_CHECK(!MulCheckedU64(UINT64_MAX, 2, &out));
  OPP_CHECK(MulCheckedU64(0, UINT64_MAX, &out));
  OPP_CHECK_EQ(out, std::uint64_t{0});
  OPP_CHECK(!AddCheckedU64(1, 1, nullptr));
}

OPP_TEST(canonical, lines_and_fields) {
  LineAssembler line("record");
  line.Add("value with space");
  line.AddU64(7);
  line.AddKeyU64("cost", 3);
  line.AddKeyToken("detail", "a b");
  const auto tokens = SplitTokens(line.text());
  OPP_REQUIRE(tokens.ok());
  OPP_CHECK_EQ(tokens.value().size(), std::size_t{5});
  OPP_CHECK_EQ(tokens.value()[1], std::string("value%20with%20space"));
  const auto cost = FindKeyedField(tokens.value(), 2, "cost");
  OPP_REQUIRE(cost.ok());
  OPP_CHECK_EQ(cost.value(), std::string("3"));
  const auto detail = FindKeyedField(tokens.value(), 2, "detail");
  OPP_REQUIRE(detail.ok());
  OPP_CHECK_EQ(DecodeToken(detail.value()).value(), std::string("a b"));
  OPP_CHECK(FindKeyedField(tokens.value(), 2, "absent").status().code == StatusCode::NotFound);

  const auto duplicate = SplitTokens("record cost=1 cost=2");
  OPP_REQUIRE(duplicate.ok());
  OPP_CHECK(FindKeyedField(duplicate.value(), 1, "cost").status().code == StatusCode::MalformedInput);

  OPP_CHECK(SplitTokens("").status().code == StatusCode::MalformedInput);
  OPP_CHECK(SplitTokens(std::string(kMaxTextLineBytes + 1, 'a')).status().code == StatusCode::LimitExceeded);
  OPP_CHECK(SplitTokens("   ").status().code == StatusCode::MalformedInput);
  OPP_CHECK(SplitTokens("a\tb").value().size() == 2);
}

OPP_TEST(canonical, byte_io) {
  ByteWriter writer;
  writer.U8(0x12);
  writer.U16(0x3456);
  writer.U32(0x789abcde);
  writer.U64(0x0102030405060708ull);
  writer.Bool(true);
  writer.Double(2.5);
  writer.Text("hello");
  writer.Bytes(std::string("\x00\x01", 2));
  const std::string bytes = writer.buffer();

  ByteReader reader(bytes);
  OPP_CHECK_EQ(reader.U8().value(), std::uint8_t{0x12});
  OPP_CHECK_EQ(reader.U16().value(), std::uint16_t{0x3456});
  OPP_CHECK_EQ(reader.U32().value(), std::uint32_t{0x789abcde});
  OPP_CHECK_EQ(reader.U64().value(), std::uint64_t{0x0102030405060708ull});
  OPP_CHECK_EQ(reader.Bool().value(), true);
  OPP_CHECK_EQ(reader.Double().value(), 2.5);
  OPP_CHECK_EQ(reader.Text().value(), std::string("hello"));
  OPP_CHECK_EQ(reader.Bytes().value(), std::string("\x00\x01", 2));
  OPP_CHECK(reader.ExpectEnd().ok());

  // The truncated prefix is bound to a named object: a reader holds a view into
  // the bytes it was constructed from, so it must not outlive them.
  const std::string truncated = bytes.substr(0, 4);
  ByteReader short_reader(truncated);
  OPP_CHECK(short_reader.U8().ok());
  OPP_CHECK(short_reader.U32().status().code == StatusCode::MalformedInput);

  ByteReader trailing(bytes);
  OPP_CHECK_EQ(trailing.U8().value(), std::uint8_t{0x12});
  OPP_CHECK(trailing.ExpectEnd().failed());

  // Non-finite doubles are refused on both sides of the wire.
  std::string nan_bytes;
  const double nan_value = NAN;
  std::uint64_t bits = 0;
  static_assert(sizeof(bits) == sizeof(nan_value));
  std::memcpy(&bits, &nan_value, sizeof(bits));
  for (int i = 7; i >= 0; --i) nan_bytes.push_back(static_cast<char>((bits >> (i * 8)) & 0xffu));
  ByteReader nan_reader(nan_bytes);
  OPP_CHECK(nan_reader.Double().status().code == StatusCode::MalformedInput);
}

OPP_TEST(sha256, reference_vectors_and_selftest) {
  std::string detail;
  OPP_CHECK_MSG(Sha256SelfTest(&detail), detail);
  OPP_CHECK_EQ(Sha256::Of(std::string_view("abc")).ToHex(),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  OPP_CHECK_EQ(Sha256::Of(std::string_view("")).ToHex(),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

OPP_TEST(spectrum, masks) {
  const SlotMask all = SlotMask::All(8);
  OPP_CHECK_EQ(all.Count(), std::uint32_t{8});
  OPP_CHECK(all.Test(7));
  OPP_CHECK(!all.Test(8));
  OPP_CHECK(all.LowestSetBit().value() == 0);

  SlotMask sparse = all;
  sparse.Reset(0);
  sparse.Reset(1);
  OPP_CHECK(sparse.LowestSetBit().value() == 2);
  // Slots 0 and 1 are blocked, so the first usable run of three starts at 2 and
  // the last one starts at 5.
  const SlotMask starts = sparse.FirstSlotMask(3);
  OPP_CHECK(!starts.Test(0));
  OPP_CHECK(!starts.Test(1));
  OPP_CHECK(starts.Test(2));
  OPP_CHECK(starts.Test(5));
  OPP_CHECK(!starts.Test(6));
  OPP_CHECK_EQ(starts.Count(), std::uint32_t{4});

  OPP_CHECK(SlotMask::None().IsEmpty());
  OPP_CHECK(!SlotMask::None().LowestSetBit().has_value());
  OPP_CHECK(SlotMask::None().FirstSlotMask(1).IsEmpty());
  OPP_CHECK(SlotMask::None().FirstSlotMask(0).IsEmpty());
  OPP_CHECK(SlotMask::All(4).IsSubsetOf(all));
  OPP_CHECK(!all.IsSubsetOf(SlotMask::All(4)));

  const auto parsed = SlotMask::FromHex(all.ToHex());
  OPP_REQUIRE(parsed.ok());
  OPP_CHECK(parsed.value() == all);
  OPP_CHECK(SlotMask::FromHex("00").status().code == StatusCode::MalformedInput);
  OPP_CHECK(SlotMask::FromHex(std::string(64, 'g')).status().code == StatusCode::MalformedInput);
  OPP_CHECK_EQ(all.ToHex().size(), std::size_t{64});
}

OPP_TEST(spectrum, model_validation) {
  SpectrumModel model;
  model.slot_count = 0;
  OPP_CHECK(model.Validate().code == StatusCode::InvalidArgument);
  model.slot_count = static_cast<std::uint16_t>(kMaxSpectrumSlots + 1);
  OPP_CHECK(model.Validate().code == StatusCode::LimitExceeded);
  model.slot_count = 96;
  OPP_CHECK(model.Validate().ok());
  OPP_CHECK_EQ(model.ChannelCapacity(1), std::uint32_t{96});
  OPP_CHECK_EQ(model.ChannelCapacity(96), std::uint32_t{1});
  OPP_CHECK_EQ(model.ChannelCapacity(97), std::uint32_t{0});
  OPP_CHECK_EQ(model.ChannelCapacity(0), std::uint32_t{0});
  OPP_CHECK_EQ(SlotWidthKhz(GridKind::Fixed50GHz), std::uint32_t{50000});
  OPP_CHECK_EQ(SlotWidthKhz(GridKind::Flex12_5GHz), std::uint32_t{12500});
  GridKind kind = GridKind::Fixed50GHz;
  OPP_CHECK(ParseGridKind("flex12_5", &kind));
  OPP_CHECK(kind == GridKind::Flex12_5GHz);
  OPP_CHECK(!ParseGridKind("bogus", &kind));
}

OPP_TEST(snapshot, build_digest_and_text_round_trip) {
  const auto built = BuildCompleteSnapshot(1, 8, 16, 8);
  OPP_REQUIRE(built.ok());
  const TopologySnapshot& snapshot = built.value();
  OPP_CHECK(snapshot.coverage_complete());
  OPP_CHECK(snapshot.conflicted_resources().empty());
  OPP_CHECK(snapshot.unresolved_references().empty());
  OPP_CHECK(snapshot.nodes().size() == 8);
  OPP_CHECK(snapshot.ArcCount() > 0);
  OPP_CHECK(snapshot.freshness() == EvidenceFreshness::Fresh);

  const std::string text = SnapshotToText(snapshot);
  const auto reparsed = ParseSnapshotText(text);
  OPP_REQUIRE(reparsed.ok());
  OPP_CHECK(reparsed.value().digest() == snapshot.digest());
  OPP_CHECK_EQ(SnapshotToText(reparsed.value()), text);

  // The same records added in a different order produce the same digest.
  const auto rebuilt = BuildCompleteSnapshot(1, 8, 16, 8);
  OPP_REQUIRE(rebuilt.ok());
  OPP_CHECK(rebuilt.value().digest() == snapshot.digest());

  const auto different = BuildCompleteSnapshot(2, 8, 16, 8);
  OPP_REQUIRE(different.ok());
  OPP_CHECK(!(different.value().digest() == snapshot.digest()));
}

OPP_TEST(snapshot, rejects_malformed_text) {
  OPP_CHECK(ParseSnapshotText("").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParseSnapshotText("OPP-SNAPSHOT 1\n").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParseSnapshotText("OPP-SNAPSHOT 99\n").status().code == StatusCode::Unsupported);
  OPP_CHECK(ParseSnapshotText("WRONG 1\n").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParseSnapshotText("OPP-SNAPSHOT 1\nid x\ngrid bogus\nslots 4\n").status().code ==
            StatusCode::Unsupported);
  OPP_CHECK(ParseSnapshotText("OPP-SNAPSHOT 1\nid a b\ngrid fixed50\nslots 4\n").status().code ==
            StatusCode::MalformedInput);
  OPP_CHECK(ParseSnapshotText("OPP-SNAPSHOT 1\nid x\ngrid fixed50\nslots 4\nnonsense 1\n").status().code ==
            StatusCode::MalformedInput);
  OPP_CHECK(ParseSnapshotText("OPP-SNAPSHOT 1\nid x\ngrid fixed50\nslots 99999\n").status().code ==
            StatusCode::MalformedInput);
  OPP_CHECK(ParseSnapshotText("OPP-SNAPSHOT 1\nid x\ngrid fixed50\nslots 0\n").status().code ==
            StatusCode::InvalidArgument);
  OPP_CHECK(ParseSnapshotText(std::string(kMaxSnapshotTextBytes + 1, 'a')).status().code ==
            StatusCode::LimitExceeded);
}

OPP_TEST(snapshot, rejects_out_of_range_spectrum) {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("bad-mask"));
  builder.SetGeneration(1);
  SpectrumModel spectrum;
  spectrum.slot_count = 4;
  builder.SetSpectrum(spectrum);

  SpanRecord span;
  span.id = SpanId::Trusted("s");
  span.from = Key("a", "x");
  span.to = Key("b", "y");
  span.length_m = Evidence<std::uint64_t>::Known(1);
  span.loss_db = Evidence<double>::Known(0.1);
  span.osnr_db = Evidence<double>::Known(30.0);
  SlotMask blocked;
  blocked.Set(9);
  span.blocked_slots = Evidence<SlotMask>::Known(blocked);
  span.admin = Evidence<AdminState>::Known(AdminState::Up);
  OPP_CHECK(builder.AddSpan(span).ok());
  const auto built = builder.Build();
  OPP_REQUIRE(!built.ok());
  OPP_CHECK(built.status().code == StatusCode::MalformedInput);
}

OPP_TEST(snapshot, rejects_self_loops_and_non_finite_quality) {
  {
    SnapshotBuilder builder;
    builder.SetId(SnapshotId::Trusted("loop"));
    SpectrumModel spectrum;
    spectrum.slot_count = 4;
    builder.SetSpectrum(spectrum);
    SpanRecord span;
    span.id = SpanId::Trusted("s");
    span.from = Key("a", "x");
    span.to = Key("a", "x");
    span.length_m = Evidence<std::uint64_t>::Known(1);
    span.loss_db = Evidence<double>::Known(0.1);
    span.osnr_db = Evidence<double>::Known(30.0);
    span.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
    span.admin = Evidence<AdminState>::Known(AdminState::Up);
    OPP_CHECK(builder.AddSpan(span).ok());
    OPP_CHECK(builder.Build().status().code == StatusCode::MalformedInput);
  }
  {
    SnapshotBuilder builder;
    builder.SetId(SnapshotId::Trusted("nonfinite"));
    SpectrumModel spectrum;
    spectrum.slot_count = 4;
    builder.SetSpectrum(spectrum);
    SpanRecord span;
    span.id = SpanId::Trusted("s");
    span.from = Key("a", "x");
    span.to = Key("b", "y");
    span.length_m = Evidence<std::uint64_t>::Known(1);
    span.loss_db = Evidence<double>::Known(INFINITY);
    span.osnr_db = Evidence<double>::Known(30.0);
    span.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
    span.admin = Evidence<AdminState>::Known(AdminState::Up);
    OPP_CHECK(builder.AddSpan(span).ok());
    OPP_CHECK(builder.Build().status().code == StatusCode::MalformedInput);
  }
}

OPP_TEST(snapshot, duplicate_records_become_conflicts) {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("dup"));
  builder.SetGeneration(1);
  SpectrumModel spectrum;
  spectrum.slot_count = 4;
  builder.SetSpectrum(spectrum);

  NodeRecord node;
  node.id = NodeId::Trusted("a");
  node.kind = NodeKind::Terminal;
  node.admin = Evidence<AdminState>::Known(AdminState::Up);
  OPP_CHECK(builder.AddNode(node).ok());
  OPP_CHECK(builder.AddNode(node).ok());
  NodeRecord other = node;
  other.kind = NodeKind::Regenerator;
  OPP_CHECK(builder.AddNode(other).ok());

  const auto built = builder.Build();
  OPP_REQUIRE(built.ok());
  OPP_CHECK_EQ(built.value().nodes().size(), std::size_t{1});
  OPP_CHECK(built.value().IsConflicted(ResourceKey::ForNode(NodeId::Trusted("a"))));
  OPP_CHECK(!built.value().coverage_complete());
}

OPP_TEST(snapshot, duplicate_sources_rejected) {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("dup-source"));
  SpectrumModel spectrum;
  spectrum.slot_count = 4;
  builder.SetSpectrum(spectrum);
  SourceRecord source;
  source.id = SourceId::Trusted("s");
  source.generation = 1;
  OPP_CHECK(builder.AddSource(source).ok());
  source.generation = 2;
  OPP_CHECK(builder.AddSource(source).ok());
  OPP_CHECK(builder.Build().status().code == StatusCode::ConflictingEvidence);
}

OPP_TEST(snapshot, unresolved_references_are_a_frontier) {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("unresolved"));
  SpectrumModel spectrum;
  spectrum.slot_count = 4;
  builder.SetSpectrum(spectrum);
  PortRecord port;
  port.key = Key("a", "in");
  port.admin = Evidence<AdminState>::Known(AdminState::Up);
  port.transmit_profile = Evidence<std::optional<ProfileId>>::Known(std::nullopt);
  port.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  OPP_CHECK(builder.AddPort(port).ok());
  SpanRecord span;
  span.id = SpanId::Trusted("s");
  span.from = Key("a", "in");
  span.to = Key("ghost", "x");
  span.length_m = Evidence<std::uint64_t>::Known(1);
  span.loss_db = Evidence<double>::Known(0.1);
  span.osnr_db = Evidence<double>::Known(30.0);
  span.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  span.admin = Evidence<AdminState>::Known(AdminState::Up);
  OPP_CHECK(builder.AddSpan(span).ok());

  const auto built = builder.Build();
  OPP_REQUIRE(built.ok());
  OPP_CHECK(!built.value().coverage_complete());
  OPP_CHECK(!built.value().unresolved_references().empty());
  OPP_CHECK(built.value().HasUnresolvedArcs(0));

  SnapshotBuildOptions strict;
  strict.allow_unresolved_references = false;
  SnapshotBuilder strict_builder(strict);
  strict_builder.SetId(SnapshotId::Trusted("strict"));
  strict_builder.SetSpectrum(spectrum);
  OPP_CHECK(strict_builder.AddPort(port).ok());
  OPP_CHECK(strict_builder.AddSpan(span).ok());
  OPP_CHECK(strict_builder.Build().status().code == StatusCode::NotFound);
}

OPP_TEST(snapshot, builder_bounds_and_sealing) {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("bounds"));
  SpectrumModel spectrum;
  spectrum.slot_count = 4;
  builder.SetSpectrum(spectrum);
  const auto built = builder.Build();
  OPP_REQUIRE(built.ok());
  // A sealed builder refuses further mutation and cannot be sealed twice.
  NodeRecord node;
  node.id = NodeId::Trusted("late");
  OPP_CHECK(builder.AddNode(node).code == StatusCode::Refused);
  OPP_CHECK(builder.Build().status().code == StatusCode::Refused);
}

OPP_TEST(request, validation_and_round_trip) {
  PlanningRequest request = BasicRequest();
  OPP_CHECK(request.Validate().ok());

  PlanningRequest no_source = request;
  no_source.source = PortKey{};
  OPP_CHECK(no_source.Validate().code == StatusCode::InvalidArgument);

  PlanningRequest same = request;
  same.destination = same.source;
  OPP_CHECK(same.Validate().code == StatusCode::InvalidArgument);

  PlanningRequest too_many = request;
  too_many.max_candidates = kMaxCandidates + 1;
  OPP_CHECK(too_many.Validate().code == StatusCode::LimitExceeded);

  PlanningRequest zero_hops = request;
  zero_hops.max_hops = 0;
  OPP_CHECK(zero_hops.Validate().code == StatusCode::InvalidArgument);

  PlanningRequest huge_search = request;
  huge_search.max_search_expansions = kMaxSearchExpansionsCeiling + 1;
  OPP_CHECK(huge_search.Validate().code == StatusCode::LimitExceeded);

  PlanningRequest unsupported = request;
  unsupported.constraints.allow_repeated_resources = true;
  OPP_CHECK(unsupported.Validate().code == StatusCode::Unsupported);

  PlanningRequest unsupported_continuity = request;
  unsupported_continuity.constraints.require_spectrum_continuity_across_regeneration = true;
  OPP_CHECK(unsupported_continuity.Validate().code == StatusCode::Unsupported);

  PlanningRequest future = request;
  future.format_version = 99;
  OPP_CHECK(future.Validate().code == StatusCode::Unsupported);

  PlanningRequest duplicated = request;
  duplicated.constraints.excluded_nodes.push_back(NodeId::Trusted("a"));
  duplicated.constraints.excluded_nodes.push_back(NodeId::Trusted("a"));
  OPP_CHECK(duplicated.Validate().code == StatusCode::DuplicateIdentity);

  request.constraints.excluded_nodes.push_back(NodeId::Trusted("n9"));
  request.constraints.excluded_spans.push_back(SpanId::Trusted("s1"));
  request.constraints.max_members_per_failure_domain[FailureDomainId::Trusted("d")] = 2;
  request.required_source_generations[SourceId::Trusted("src")] = 4;
  request.constraints.max_total_distance_m = 1000;
  request.constraints.max_total_loss_db = 12.5;
  request.constraints.min_segment_osnr_db = 9.5;
  request.disjointness = Disjointness::Span;
  request.max_candidates = 3;

  const std::string text = RequestToText(request);
  const auto reparsed = ParseRequestText(text);
  OPP_REQUIRE(reparsed.ok());
  OPP_CHECK_EQ(RequestToText(reparsed.value()), text);
  OPP_CHECK(reparsed.value().required_source_generations == request.required_source_generations);
  OPP_CHECK(reparsed.value().constraints.max_total_loss_db.value() == 12.5);
  OPP_CHECK(reparsed.value().disjointness == Disjointness::Span);
  OPP_CHECK(ComputeRequestDigest(request) == ComputeRequestDigest(reparsed.value()));

  OPP_CHECK(ParseRequestText("").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParseRequestText("OPP-REQUEST 99\n").status().code == StatusCode::Unsupported);
  OPP_CHECK(ParseRequestText("OPP-REQUEST 1\nid r\n").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParseRequestText("OPP-REQUEST 1\nid r\nsource a in\ndestination b out\nbogus 1\n").status().code ==
            StatusCode::MalformedInput);
}

OPP_TEST(planner, feasible_is_deterministic_and_byte_stable) {
  const auto built = BuildCompleteSnapshot(5, 10, 16, 8);
  OPP_REQUIRE(built.ok());
  const PlanningRequest request = BasicRequest();
  const Planner planner;
  const PlanningResult first = planner.Plan(built.value(), request);
  const PlanningResult second = planner.Plan(built.value(), request);
  OPP_CHECK(first.outcome == second.outcome);
  OPP_CHECK_EQ(first.CanonicalBytes(), second.CanonicalBytes());
  OPP_CHECK(first.result_digest == second.result_digest);
  if (first.outcome == PlanOutcome::Feasible) {
    OPP_REQUIRE(!first.candidates.empty());
    OPP_CHECK_EQ(first.candidates.front().CanonicalBytes(), second.candidates.front().CanonicalBytes());
    OPP_CHECK(first.candidates.front().digest == second.candidates.front().digest);
    OPP_CHECK(first.candidates.front().VerifySeal().ok());
  }
}

OPP_TEST(planner, missing_endpoint_with_complete_coverage_is_infeasible) {
  const auto built = BuildCompleteSnapshot(5, 10, 16, 0);
  OPP_REQUIRE(built.ok());
  PlanningRequest request = BasicRequest();
  request.destination = Key("does-not-exist", "c0");
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  OPP_CHECK(result.outcome == PlanOutcome::Infeasible);
  OPP_REQUIRE(!result.cuts.empty());
  OPP_CHECK(result.cuts.front().reason == CutReason::DestinationAbsent);
}

OPP_TEST(planner, missing_endpoint_with_partial_coverage_is_indeterminate) {
  SnapshotBuilder builder;
  builder.SetId(SnapshotId::Trusted("partial-coverage"));
  SpectrumModel spectrum;
  spectrum.slot_count = 4;
  builder.SetSpectrum(spectrum);
  SourceRecord source;
  source.id = SourceId::Trusted("s");
  source.generation = 1;
  source.coverage = Coverage::Partial;
  OPP_CHECK(builder.AddSource(source).ok());
  PortRecord port;
  port.key = Key("a", "in");
  port.admin = Evidence<AdminState>::Known(AdminState::Up);
  port.transmit_profile = Evidence<std::optional<ProfileId>>::Known(std::nullopt);
  port.blocked_slots = Evidence<SlotMask>::Known(SlotMask::None());
  OPP_CHECK(builder.AddPort(port).ok());
  const auto built = builder.Build();
  OPP_REQUIRE(built.ok());
  OPP_CHECK(!built.value().coverage_complete());

  PlanningRequest request;
  request.id = RequestId::Trusted("partial");
  request.source = Key("a", "in");
  request.destination = Key("ghost", "in");
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  OPP_CHECK(result.outcome == PlanOutcome::Indeterminate);
  OPP_CHECK((result.limitations & kLimitationUnknownAdjacency) != 0);
}

OPP_TEST(planner, disconnected_is_infeasible) {
  const auto built = opp_test::BuildTwoNodeSnapshot(Evidence<double>::Known(30.0));
  OPP_REQUIRE(built.ok());
  PlanningRequest request;
  request.id = RequestId::Trusted("disconnected");
  request.source = Key("a", "in");
  request.destination = Key("a", "out");
  const Planner planner;
  // A reachable pair, then an unreachable one.
  const PlanningResult reachable = planner.Plan(built.value(), request);
  OPP_CHECK(reachable.outcome == PlanOutcome::Feasible);

  PlanningRequest reverse;
  reverse.id = RequestId::Trusted("disconnected-reverse");
  reverse.source = Key("b", "out");
  reverse.destination = Key("a", "in");
  const PlanningResult unreachable = planner.Plan(built.value(), reverse);
  OPP_CHECK(unreachable.outcome == PlanOutcome::Infeasible);
  OPP_CHECK(unreachable.candidates.empty());
}

OPP_TEST(planner, unknown_quality_is_indeterminate_not_infeasible) {
  const auto built = opp_test::BuildTwoNodeSnapshot(Evidence<double>::Unknown());
  OPP_REQUIRE(built.ok());
  PlanningRequest request;
  request.id = RequestId::Trusted("unknown-osnr");
  request.source = Key("a", "in");
  request.destination = Key("b", "in");
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  OPP_CHECK(result.outcome == PlanOutcome::Indeterminate);
  OPP_CHECK(result.candidates.empty());
  OPP_CHECK((result.limitations & kLimitationUnknownQualityField) != 0);
  OPP_REQUIRE(!result.witnesses.empty());
  OPP_CHECK(result.witnesses.front().reason == CutReason::UnknownQualityField);

  // The same shape with the quantity published is provably feasible, which
  // proves the difference came from the missing value and nothing else.
  const auto published = opp_test::BuildTwoNodeSnapshot(Evidence<double>::Known(30.0));
  OPP_REQUIRE(published.ok());
  const PlanningResult proven = planner.Plan(published.value(), request);
  OPP_CHECK(proven.outcome == PlanOutcome::Feasible);
}

OPP_TEST(planner, partial_coverage_frontier_is_indeterminate) {
  const auto built = opp_test::BuildPartialCoverageSnapshot();
  OPP_REQUIRE(built.ok());
  OPP_CHECK(!built.value().coverage_complete());
  PlanningRequest request;
  request.id = RequestId::Trusted("partial-frontier");
  request.source = Key("a", "in");
  request.destination = Key("a", "out");
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  // A proven route exists here, so the frontier does not change the outcome.
  OPP_CHECK(result.outcome == PlanOutcome::Feasible);

  PlanningRequest unreachable;
  unreachable.id = RequestId::Trusted("partial-unreachable");
  unreachable.source = Key("a", "in");
  unreachable.destination = Key("b", "out");
  const PlanningResult frontier = planner.Plan(built.value(), unreachable);
  OPP_CHECK_MSG(frontier.outcome == PlanOutcome::Indeterminate,
                std::string("outcome was ") + PlanOutcomeName(frontier.outcome));
  OPP_CHECK((frontier.limitations & kLimitationUnknownAdjacency) != 0);
}

OPP_TEST(planner, stale_requirements_are_indeterminate) {
  const auto built = BuildCompleteSnapshot(5, 8, 8, 0);
  OPP_REQUIRE(built.ok());
  const Planner planner;

  PlanningRequest stale_source = BasicRequest();
  stale_source.required_source_generations[SourceId::Trusted("synthetic-generator")] = 99;
  const PlanningResult stale = planner.Plan(built.value(), stale_source);
  OPP_CHECK(stale.outcome == PlanOutcome::Indeterminate);
  OPP_CHECK(stale.status.code == StatusCode::Stale);
  OPP_CHECK((stale.limitations & kLimitationStaleEvidence) != 0);

  PlanningRequest absent_source = BasicRequest();
  absent_source.required_source_generations[SourceId::Trusted("nobody")] = 1;
  OPP_CHECK(planner.Plan(built.value(), absent_source).outcome == PlanOutcome::Indeterminate);

  PlanningRequest stale_snapshot = BasicRequest();
  stale_snapshot.required_snapshot_generation = built.value().generation() + 1;
  OPP_CHECK(planner.Plan(built.value(), stale_snapshot).outcome == PlanOutcome::Indeterminate);

  PlanningRequest wrong_digest = BasicRequest();
  wrong_digest.expected_snapshot_digest = Digest256{};
  OPP_CHECK(planner.Plan(built.value(), wrong_digest).outcome == PlanOutcome::Indeterminate);

  PlanningRequest satisfied = BasicRequest();
  satisfied.required_source_generations[SourceId::Trusted("synthetic-generator")] = built.value().generation();
  satisfied.expected_snapshot_digest = built.value().digest();
  OPP_CHECK(planner.Plan(built.value(), satisfied).outcome == PlanOutcome::Feasible);
}

OPP_TEST(planner, restored_evidence_is_not_fresh) {
  auto built = BuildCompleteSnapshot(5, 8, 8, 0);
  OPP_REQUIRE(built.ok());
  TopologySnapshot restored = built.value();
  restored.MarkRestored(IncarnationId{}, 7);
  OPP_CHECK(restored.freshness() == EvidenceFreshness::Restored);
  // The content digest is unchanged: freshness is metadata, not content.
  OPP_CHECK(restored.digest() == built.value().digest());

  const Planner planner;
  const PlanningRequest request = BasicRequest();
  const PlanningResult refused = planner.Plan(restored, request);
  OPP_CHECK(refused.outcome == PlanOutcome::Indeterminate);
  OPP_CHECK((refused.limitations & kLimitationRestoredEvidence) != 0);

  PlanningRequest accepted = request;
  accepted.accept_restored_evidence = true;
  OPP_CHECK(planner.Plan(restored, accepted).outcome == PlanOutcome::Feasible);
}

OPP_TEST(planner, unsupported_and_refused_are_distinct) {
  const auto built = BuildCompleteSnapshot(5, 8, 8, 0);
  OPP_REQUIRE(built.ok());
  const Planner planner;

  PlanningRequest unsupported = BasicRequest();
  unsupported.constraints.require_spectrum_continuity_across_regeneration = true;
  const PlanningResult unsupported_result = planner.Plan(built.value(), unsupported);
  OPP_CHECK(unsupported_result.outcome == PlanOutcome::Unsupported);
  OPP_CHECK(unsupported_result.candidates.empty());

  PlanningRequest refused = BasicRequest();
  refused.max_candidates = kMaxCandidates + 1;
  const PlanningResult refused_result = planner.Plan(built.value(), refused);
  OPP_CHECK(refused_result.outcome == PlanOutcome::Refused);
  OPP_CHECK(refused_result.status.code == StatusCode::LimitExceeded);

  PlanningRequest fixed_grid_width = BasicRequest();
  fixed_grid_width.channel_width_slots = 2;
  const PlanningResult width_result = planner.Plan(built.value(), fixed_grid_width);
  OPP_CHECK(width_result.outcome == PlanOutcome::Unsupported);
}

OPP_TEST(planner, exclusions_change_the_outcome) {
  const auto built = opp_test::BuildTwoNodeSnapshot(Evidence<double>::Known(30.0));
  OPP_REQUIRE(built.ok());
  const Planner planner;
  const PlanningRequest request = [] {
    PlanningRequest r;
    r.id = RequestId::Trusted("exclusion");
    r.source = Key("a", "in");
    r.destination = Key("b", "in");
    return r;
  }();
  OPP_CHECK(planner.Plan(built.value(), request).outcome == PlanOutcome::Feasible);

  PlanningRequest exclude_span = request;
  exclude_span.constraints.excluded_spans.push_back(SpanId::Trusted("s"));
  const PlanningResult span_result = planner.Plan(built.value(), exclude_span);
  OPP_CHECK(span_result.outcome == PlanOutcome::Infeasible);
  OPP_CHECK(std::any_of(span_result.cuts.begin(), span_result.cuts.end(), [](const CutCount& cut) {
    return cut.reason == CutReason::SpanExcluded;
  }));

  PlanningRequest exclude_node = request;
  exclude_node.constraints.excluded_nodes.push_back(NodeId::Trusted("b"));
  OPP_CHECK(planner.Plan(built.value(), exclude_node).outcome == PlanOutcome::Infeasible);

  PlanningRequest exclude_domain = request;
  exclude_domain.constraints.max_members_per_failure_domain.clear();
  PlanningRequest exclude_port = request;
  exclude_port.constraints.excluded_ports.push_back(Key("a", "out"));
  OPP_CHECK(planner.Plan(built.value(), exclude_port).outcome == PlanOutcome::Infeasible);

  PlanningRequest exclude_cross_connect = request;
  exclude_cross_connect.constraints.excluded_cross_connects.push_back(CrossConnectId::Trusted("x-a"));
  OPP_CHECK(planner.Plan(built.value(), exclude_cross_connect).outcome == PlanOutcome::Infeasible);
}

OPP_TEST(planner, plan_carries_bound_generations_and_reasons) {
  const auto built = BuildCompleteSnapshot(5, 10, 16, 8);
  OPP_REQUIRE(built.ok());
  PlanningRequest request = BasicRequest();
  request.max_candidates = 2;
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  const PlanArtifact& plan = result.candidates.front();
  OPP_CHECK(plan.snapshot_digest == built.value().digest());
  OPP_CHECK_EQ(plan.snapshot_id.str(), built.value().id().str());
  OPP_CHECK_EQ(plan.snapshot_generation, built.value().generation());
  OPP_CHECK(!plan.bound_sources.empty());
  for (const SourceBinding& binding : plan.bound_sources) {
    OPP_CHECK(built.value().HasSource(binding.source));
    OPP_CHECK_EQ(binding.generation, built.value().SourceGeneration(binding.source));
  }
  OPP_CHECK(!plan.steps.empty());
  OPP_CHECK(!plan.segments.empty());
  OPP_CHECK(!plan.reservations.empty());
  OPP_CHECK(!plan.capability_assumptions.empty());
  OPP_CHECK(!plan.quality_assumptions.empty());
  for (const PlanStep& step : plan.steps) {
    OPP_CHECK(step.reason_bits != 0);
    OPP_CHECK(!step.resource.empty());
  }
  for (const PlanAssumption& assumption : plan.capability_assumptions) {
    OPP_CHECK(!assumption.resource.empty());
    OPP_CHECK(!assumption.field.empty());
    OPP_CHECK(!assumption.value.empty());
  }
  OPP_CHECK_EQ(plan.steps.front().resource, ResourceKey::ForPort(request.source));
  OPP_CHECK_EQ(plan.steps.back().resource, ResourceKey::ForPort(request.destination));
  OPP_CHECK_EQ(plan.channel_width_slots, request.channel_width_slots);
  // hops counts traversed arcs: spans plus cross-connects.
  std::uint32_t arc_steps = 0;
  for (const PlanStep& step : plan.steps) {
    if (step.kind == StepKind::Span || step.kind == StepKind::CrossConnect) arc_steps += 1;
  }
  OPP_CHECK_EQ(plan.hops, arc_steps);
  std::uint32_t total_spans = 0;
  for (const PlanSegment& segment : plan.segments) total_spans += segment.span_count;
  OPP_CHECK(total_spans >= 1);
  OPP_CHECK(arc_steps >= total_spans);
}

OPP_TEST(plan, codec_round_trip_and_tamper_detection) {
  const auto built = BuildCompleteSnapshot(6, 10, 16, 8);
  OPP_REQUIRE(built.ok());
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), BasicRequest());
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  const PlanArtifact& plan = result.candidates.front();
  const std::string bytes = plan.CanonicalBytes();

  const auto parsed = ParsePlanArtifact(bytes);
  OPP_REQUIRE(parsed.ok());
  OPP_CHECK(parsed.value().digest == plan.digest);
  OPP_CHECK_EQ(parsed.value().CanonicalBytes(), bytes);

  // Any change to the content invalidates the seal.
  std::string tampered = bytes;
  const std::size_t position = tampered.find("totals cost=");
  OPP_REQUIRE(position != std::string::npos);
  tampered[position + 12] = tampered[position + 12] == '9' ? '8' : '9';
  const auto tampered_result = ParsePlanArtifact(tampered);
  OPP_CHECK(!tampered_result.ok());
  OPP_CHECK(tampered_result.status().code == StatusCode::IntegrityFailure);

  // Truncation, trailing content and revision drift are all rejected.
  OPP_CHECK(ParsePlanArtifact(bytes.substr(0, bytes.size() / 2)).status().code == StatusCode::MalformedInput ||
            ParsePlanArtifact(bytes.substr(0, bytes.size() / 2)).status().code == StatusCode::IntegrityFailure);
  OPP_CHECK(ParsePlanArtifact(bytes + "step 99 kind=node seg=0 reason=0 cost=0 res=node:x\n").status().code ==
            StatusCode::MalformedInput);
  OPP_CHECK(ParsePlanArtifact("OPP-PLAN 99\n").status().code == StatusCode::Unsupported);
  OPP_CHECK(ParsePlanArtifact("").status().code == StatusCode::MalformedInput);
  OPP_CHECK(ParsePlanArtifact("OPP-PLAN 1\n").status().code == StatusCode::MalformedInput);

  PlanArtifact resealed = plan;
  resealed.Seal();
  OPP_CHECK(resealed.digest == plan.digest);
}

OPP_TEST(plan, canonical_ordering_is_total) {
  const auto built = BuildCompleteSnapshot(7, 12, 16, 8);
  OPP_REQUIRE(built.ok());
  PlanningRequest request = BasicRequest();
  request.max_candidates = 4;
  request.disjointness = Disjointness::Span;
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), request);
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  for (std::size_t i = 1; i < result.candidates.size(); ++i) {
    const bool ordered = PlanLess(result.candidates[i - 1], result.candidates[i]) ||
                         (!PlanLess(result.candidates[i], result.candidates[i - 1]) &&
                          result.candidates[i - 1].digest == result.candidates[i].digest);
    OPP_CHECK_MSG(ordered, "candidates are not in canonical order");
  }
}

OPP_TEST(result, codec_round_trip) {
  const auto built = BuildCompleteSnapshot(8, 10, 16, 8);
  OPP_REQUIRE(built.ok());
  const Planner planner;

  for (const bool feasible : {true, false}) {
    PlanningRequest request = BasicRequest();
    if (!feasible) request.destination = Key("ghost", "c0");
    const PlanningResult result = planner.Plan(built.value(), request);
    const std::string bytes = result.CanonicalBytes();
    const auto reparsed = ParseResultText(bytes);
    OPP_REQUIRE(reparsed.ok());
    OPP_CHECK(reparsed.value().result_digest == result.result_digest);
    OPP_CHECK(reparsed.value().outcome == result.outcome);
    OPP_CHECK_EQ(reparsed.value().candidates.size(), result.candidates.size());
    OPP_CHECK_EQ(reparsed.value().CanonicalBytes(), bytes);
  }

  PlanningResult empty;
  empty.outcome = PlanOutcome::Indeterminate;
  empty.status = Failure(StatusCode::Stale, "detail with spaces and % signs");
  empty.limitations = kLimitationStaleEvidence | kLimitationUnknownSpectrum;
  empty.Seal();
  const auto parsed = ParseResultText(empty.CanonicalBytes());
  OPP_REQUIRE(parsed.ok());
  OPP_CHECK_EQ(parsed.value().status.detail, std::string("detail with spaces and % signs"));
  OPP_CHECK_EQ(parsed.value().limitations, empty.limitations);
}

OPP_TEST(store, round_trip_idempotence_and_capacity) {
  const std::string root = opp_test::FreshTempDir("store-round-trip");
  const auto built = BuildCompleteSnapshot(9, 10, 16, 8);
  OPP_REQUIRE(built.ok());
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), BasicRequest());
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  const PlanArtifact& plan = result.candidates.front();

  StoreOptions options;
  options.root = root;
  options.max_plans = 2;
  const auto store = PlanStore::Open(options);
  OPP_REQUIRE(store.ok());
  OPP_CHECK_EQ(store.value()->Count(), std::uint32_t{0});
  OPP_CHECK(store.value()->Put(plan).ok());
  OPP_CHECK(store.value()->Put(plan).ok());
  OPP_CHECK_EQ(store.value()->Count(), std::uint32_t{1});
  OPP_CHECK(store.value()->Contains(plan.digest));

  const auto fetched = store.value()->Get(plan.digest);
  OPP_REQUIRE(fetched.ok());
  OPP_CHECK_EQ(fetched.value().CanonicalBytes(), plan.CanonicalBytes());
  OPP_CHECK(store.value()->GetByHex(plan.DigestHex()).ok());
  OPP_CHECK(store.value()->GetByHex("not-hex").status().code == StatusCode::MalformedInput);
  OPP_CHECK(store.value()->Get(Digest256{}).status().code == StatusCode::NotFound);

  std::vector<StoreEntry> entries;
  std::vector<std::string> rejected;
  OPP_CHECK(store.value()->List(&entries, &rejected).ok());
  OPP_CHECK_EQ(entries.size(), std::size_t{1});
  OPP_CHECK(rejected.empty());
  OPP_CHECK_EQ(entries.front().digest, plan.digest);

  // A store that cannot hold another artifact refuses rather than evicting.
  const auto second = planner.Plan(built.value(), BasicRequest());
  OPP_REQUIRE(second.outcome == PlanOutcome::Feasible);
  PlanArtifact other = second.candidates.front();
  other.request_id = RequestId::Trusted("other");
  other.Seal();
  OPP_CHECK(store.value()->Put(other).ok());
  PlanArtifact third = other;
  third.request_id = RequestId::Trusted("third");
  third.Seal();
  OPP_CHECK(store.value()->Put(third).code == StatusCode::Exhausted);

  OPP_CHECK(store.value()->Remove(plan.digest).ok());
  OPP_CHECK(store.value()->Remove(plan.digest).code == StatusCode::NotFound);
  opp_test::RemoveTree(root);
}

OPP_TEST(store, rejects_corrupt_truncated_and_partial_files) {
  const std::string root = opp_test::FreshTempDir("store-corrupt");
  const auto built = BuildCompleteSnapshot(10, 10, 16, 8);
  OPP_REQUIRE(built.ok());
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), BasicRequest());
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  const PlanArtifact& plan = result.candidates.front();

  StoreOptions options;
  options.root = root;
  const auto store = PlanStore::Open(options);
  OPP_REQUIRE(store.ok());
  OPP_REQUIRE(store.value()->Put(plan).ok());

  // A partially written temporary is cleaned up on open and never read.
  const std::string plans_dir = root + "/plans";
  const auto encoded = EncodeStoreFile(plan);
  OPP_REQUIRE(encoded.ok());
  const Status temporary_write = WriteFileAtomic(plans_dir + "/leftover.opptmp", encoded.value().substr(0, 10));
  OPP_REQUIRE(temporary_write.ok());
  const auto reopened = PlanStore::Open(options);
  OPP_REQUIRE(reopened.ok());
  std::vector<StoreEntry> entries;
  std::vector<std::string> rejected;
  OPP_CHECK(reopened.value()->List(&entries, &rejected).ok());
  OPP_CHECK_EQ(entries.size(), std::size_t{1});
  OPP_CHECK(rejected.empty());

  // Truncation is detected rather than silently accepted.
  const std::string path = plans_dir + "/" + plan.DigestHex() + ".oppplan";
  OPP_REQUIRE(WriteFileAtomic(path, encoded.value().substr(0, encoded.value().size() - 8)).ok());
  OPP_CHECK(!reopened.value()->Get(plan.digest).ok());
  OPP_CHECK(reopened.value()->List(&entries, &rejected).ok());
  OPP_CHECK(entries.empty());
  OPP_CHECK_EQ(rejected.size(), std::size_t{1});

  // A flipped payload byte fails the checksum.
  std::string flipped = encoded.value();
  flipped[flipped.size() / 2] = static_cast<char>(flipped[flipped.size() / 2] ^ 0x01);
  OPP_REQUIRE(WriteFileAtomic(path, flipped).ok());
  OPP_CHECK(reopened.value()->Get(plan.digest).status().code == StatusCode::IntegrityFailure);

  // Wrong magic and wrong revision are distinguished.
  std::string wrong_magic = encoded.value();
  wrong_magic[0] = 'X';
  OPP_REQUIRE(WriteFileAtomic(path, wrong_magic).ok());
  OPP_CHECK(reopened.value()->Get(plan.digest).status().code == StatusCode::MalformedInput);

  OPP_CHECK(DecodeStoreFile("").status().code == StatusCode::Truncated);
  OPP_CHECK(DecodeStoreFile(encoded.value().substr(0, 4)).status().code == StatusCode::Truncated);
  opp_test::RemoveTree(root);
}

OPP_TEST(validate, bindings_and_staleness) {
  const auto built = BuildCompleteSnapshot(11, 10, 16, 8);
  OPP_REQUIRE(built.ok());
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), BasicRequest());
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  const PlanArtifact& plan = result.candidates.front();

  OPP_CHECK(ValidatePlanBindings(plan, built.value()).validity == PlanValidity::Valid);

  const auto newer = BuildCompleteSnapshot(11, 10, 16, 8);
  OPP_REQUIRE(newer.ok());
  TopologySnapshot changed = built.value();
  changed = newer.value();
  OPP_CHECK(ValidatePlanBindings(plan, changed).validity == PlanValidity::Valid);

  // A generation bump invalidates the plan even when the route still exists.
  SyntheticOptions options;
  options.seed = 11;
  options.node_count = 10;
  options.degree = 3;
  options.slot_count = 16;
  options.slot_blocking_one_in = 8;
  options.generation = built.value().generation() + 1;
  const auto regenerated = GenerateSyntheticTopology(options);
  OPP_REQUIRE(regenerated.ok());
  const ValidationReport stale = ValidatePlanBindings(plan, regenerated.value());
  OPP_CHECK(stale.validity == PlanValidity::Stale);
  OPP_REQUIRE(!stale.source_mismatches.empty());
  OPP_CHECK_EQ(stale.source_mismatches.front().bound, built.value().generation());
  OPP_CHECK_EQ(stale.source_mismatches.front().current, regenerated.value().generation());

  TopologySnapshot restored = built.value();
  restored.MarkRestored(IncarnationId{}, 3);
  OPP_CHECK(ValidatePlanBindings(plan, restored).validity == PlanValidity::NotFresh);
  ValidationPolicy accepting;
  accepting.accept_restored_evidence = true;
  OPP_CHECK(ValidatePlanBindings(plan, restored, accepting).validity == PlanValidity::Valid);

  PlanArtifact broken = plan;
  broken.steps.front().reason_bits ^= 0x1u;
  OPP_CHECK(ValidatePlanBindings(broken, built.value()).validity == PlanValidity::IntegrityFailure);

  PlanArtifact future = plan;
  future.rule_version = kPlanningRuleVersion + 1;
  future.Seal();
  OPP_CHECK(ValidatePlanBindings(future, built.value()).validity == PlanValidity::Unsupported);
}

OPP_TEST(validate, revalidation_reproduces_every_decision) {
  const auto built = BuildCompleteSnapshot(12, 10, 16, 8);
  OPP_REQUIRE(built.ok());
  const Planner planner;
  const PlanningResult result = planner.Plan(built.value(), BasicRequest());
  OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
  const PlanArtifact& plan = result.candidates.front();

  const ValidationReport report = RevalidatePlan(plan, built.value());
  OPP_CHECK(report.validity == PlanValidity::Valid);
  OPP_CHECK(report.revalidated);
  OPP_CHECK(report.failures.empty());

  // Rebuild the same fabric with one port moved out of service. Revalidation must
  // re-derive that decision and report it, even though the plan content is intact
  // and the evidence generations are unchanged.
  SnapshotBuilder builder;
  builder.SetId(built.value().id());
  builder.SetGeneration(built.value().generation());
  builder.SetSpectrum(built.value().spectrum());
  for (const SourceRecord& source : built.value().sources()) {
    OPP_REQUIRE(builder.AddSource(source).ok());
  }
  for (const ReachProfile& profile : built.value().reach_profiles()) {
    OPP_REQUIRE(builder.AddReachProfile(profile).ok());
  }
  for (const NodeRecord& node : built.value().nodes()) {
    OPP_REQUIRE(builder.AddNode(node).ok());
  }
  const PortKey flagged = plan.source;
  for (const PortRecord& port : built.value().ports()) {
    PortRecord candidate = port;
    if (port.key == flagged) {
      candidate.admin = Evidence<AdminState>::Known(AdminState::Down);
    }
    OPP_REQUIRE(builder.AddPort(candidate).ok());
  }
  for (const CrossConnectRecord& cross_connect : built.value().cross_connects()) {
    OPP_REQUIRE(builder.AddCrossConnect(cross_connect).ok());
  }
  for (const SpanRecord& span : built.value().spans()) {
    OPP_REQUIRE(builder.AddSpan(span).ok());
  }
  const auto degraded = builder.Build();
  OPP_REQUIRE(degraded.ok());

  // The rebuilt snapshot has a different content digest even though the source
  // generations are unchanged, so re-derivation has to be requested explicitly.
  ValidationPolicy revalidate_anyway;
  revalidate_anyway.revalidate_on_mismatch = true;
  const ValidationReport degraded_report = RevalidatePlan(plan, degraded.value(), revalidate_anyway);
  OPP_CHECK(degraded_report.revalidated);
  OPP_CHECK(!degraded_report.ok());
  OPP_CHECK(!degraded_report.failures.empty());
  bool saw_admin_failure = false;
  for (const RevalidationFailure& failure : degraded_report.failures) {
    OPP_CHECK(!failure.detail.empty());
    if (failure.reason == CutReason::DestinationAdminDown || failure.reason == CutReason::SpanAdminDown ||
        failure.reason == CutReason::CrossConnectAdminDown) {
      saw_admin_failure = true;
    }
  }
  OPP_CHECK_MSG(saw_admin_failure, "revalidation did not report the resource that left service");
}

OPP_TEST(synthetic, generator_is_reproducible) {
  SyntheticOptions options;
  options.seed = 99;
  options.node_count = 9;
  options.degree = 3;
  options.slot_count = 12;
  const auto first = GenerateSyntheticTopology(options);
  const auto second = GenerateSyntheticTopology(options);
  OPP_REQUIRE(first.ok());
  OPP_REQUIRE(second.ok());
  OPP_CHECK_EQ(SnapshotToText(first.value()), SnapshotToText(second.value()));
  OPP_CHECK(first.value().digest() == second.value().digest());
  OPP_CHECK(first.value().coverage_complete());

  SyntheticOptions bad = options;
  bad.node_count = 1;
  OPP_CHECK(GenerateSyntheticTopology(bad).status().code == StatusCode::InvalidArgument);
  bad = options;
  bad.node_count = kMaxGeneratedNodes + 1;
  OPP_CHECK(GenerateSyntheticTopology(bad).status().code == StatusCode::LimitExceeded);
  bad = options;
  bad.degree = 1;
  OPP_CHECK(GenerateSyntheticTopology(bad).status().code == StatusCode::InvalidArgument);
  bad = options;
  bad.degree = options.node_count;
  OPP_CHECK(GenerateSyntheticTopology(bad).status().code == StatusCode::InvalidArgument);
  bad = options;
  bad.client_ports = 0;
  OPP_CHECK(GenerateSyntheticTopology(bad).status().code == StatusCode::InvalidArgument);
}

OPP_TEST(library, selftest_and_version) {
  const Status status = SelfTest();
  OPP_CHECK_MSG(status.ok(), status.detail);
  OPP_CHECK_EQ(std::string(VersionString()), std::string("1.0.0"));
  OPP_CHECK_EQ(std::string(LibraryName()), std::string("OpticalPathPlanner"));
  OPP_CHECK(std::string(BuildIdentification()).size() > 0);
  OPP_CHECK_EQ(kSnapshotFormatVersion, 1u);
  OPP_CHECK_EQ(kPlanFormatVersion, 1u);
  OPP_CHECK_EQ(kStoreFormatVersion, 1u);
  OPP_CHECK_EQ(kProtocolVersion, 1u);
}
