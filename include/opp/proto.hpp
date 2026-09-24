#pragma once

// Framed transport for the inspection service.
//
// Frames are length delimited, versioned and checksummed. Every frame carries the
// epoch the client believes is current; the service rejects a frame whose epoch
// is older than its own, which is what fences clients that survived a restart.

#include <cstdint>
#include <string>
#include <vector>

#include "opp/ids.hpp"
#include "opp/plan.hpp"
#include "opp/request.hpp"
#include "opp/result.hpp"
#include "opp/status.hpp"
#include "opp/topology.hpp"
#include "opp/validate.hpp"
#include "opp/version.hpp"

namespace opp {

inline constexpr std::uint32_t kFrameMagic = 0x3150504fu;  // "OPP1" little endian
inline constexpr const char* kServiceBindAddress = "127.0.0.1";

enum class MessageKind : std::uint32_t {
  Hello = 1,
  HelloAck = 2,
  Ingest = 3,
  IngestAck = 4,
  Plan = 5,
  PlanAck = 6,
  Validate = 7,
  ValidateAck = 8,
  GetPlan = 9,
  GetPlanAck = 10,
  StoreList = 11,
  StoreListAck = 12,
  Cancel = 13,
  CancelAck = 14,
  Stats = 15,
  StatsAck = 16,
  Shutdown = 17,
  ShutdownAck = 18,
  Failure = 19,
};

const char* MessageKindName(MessageKind kind) noexcept;

struct Frame {
  MessageKind kind = MessageKind::Hello;
  std::uint64_t sequence = 0;
  Epoch epoch_pin = 0;
  std::string payload;

  [[nodiscard]] bool IsRequest() const noexcept;
};

// Encodes a frame with magic, revision, routing fields, payload and checksum.
[[nodiscard]] std::string EncodeFrame(const Frame& frame);

// Decodes exactly one frame from the front of bytes. Trailing bytes are ignored
// so that a stream buffer can be drained incrementally; use FrameSize to learn
// how many bytes were consumed.
[[nodiscard]] Expected<Frame> DecodeFrame(std::string_view bytes, std::size_t* consumed);

// Length of the frame at the front of bytes, or NotFound when incomplete.
[[nodiscard]] Expected<std::size_t> FrameSize(std::string_view bytes);

// Payload codecs. One struct per message; encode and decode are total and
// bounded.
struct HelloMessage {
  std::uint32_t protocol_version = kProtocolVersion;
  std::string client_name;
};
struct HelloAckMessage {
  std::uint32_t protocol_version = kProtocolVersion;
  std::string library_version;
  IncarnationId incarnation{};
  Epoch epoch = 0;
  bool epoch_continuity = true;
  bool has_snapshot = false;
  bool snapshot_fresh = false;
  SnapshotId snapshot_id;
  Generation snapshot_generation = 0;
  Digest256 snapshot_digest{};
};
struct IngestMessage {
  Digest256 snapshot_digest{};
  std::string snapshot_text;
};
struct IngestAckMessage {
  SnapshotId snapshot_id;
  Generation generation = 0;
  Digest256 snapshot_digest{};
};
struct PlanMessage {
  std::uint64_t cancel_token = 0;
  std::string request_text;
};
struct PlanAckMessage {
  std::string result_text;
};
struct ValidateMessage {
  ValidationPolicy policy;
  std::string plan_text;
};
struct ValidateAckMessage {
  PlanValidity validity = PlanValidity::Refused;
  std::string report_text;
};
struct GetPlanMessage {
  Digest256 digest{};
};
struct GetPlanAckMessage {
  Digest256 digest{};
  std::string plan_text;
};
struct StoreListAckMessage {
  std::vector<Digest256> digests;
  std::vector<std::string> rejected_files;
};
struct CancelMessage {
  std::uint64_t cancel_token = 0;
};
struct CancelAckMessage {
  bool found = false;
};
struct StatsAckMessage {
  IncarnationId incarnation{};
  Epoch epoch = 0;
  std::uint64_t connections_accepted = 0;
  std::uint64_t frames_handled = 0;
  std::uint64_t frames_rejected = 0;
  std::uint64_t snapshots_ingested = 0;
  std::uint64_t plans_computed = 0;
  std::uint64_t plans_rejected = 0;
  std::uint64_t plans_cancelled = 0;
  std::uint64_t active_requests = 0;
  std::uint64_t stored_plans = 0;
  std::uint64_t fenced_frames = 0;
};

[[nodiscard]] std::string EncodeHello(const HelloMessage& message);
[[nodiscard]] Expected<HelloMessage> DecodeHello(std::string_view payload);
[[nodiscard]] std::string EncodeHelloAck(const HelloAckMessage& message);
[[nodiscard]] Expected<HelloAckMessage> DecodeHelloAck(std::string_view payload);
[[nodiscard]] std::string EncodeIngest(const IngestMessage& message);
[[nodiscard]] Expected<IngestMessage> DecodeIngest(std::string_view payload);
[[nodiscard]] std::string EncodeIngestAck(const IngestAckMessage& message);
[[nodiscard]] Expected<IngestAckMessage> DecodeIngestAck(std::string_view payload);
[[nodiscard]] std::string EncodePlan(const PlanMessage& message);
[[nodiscard]] Expected<PlanMessage> DecodePlan(std::string_view payload);
[[nodiscard]] std::string EncodePlanAck(const PlanAckMessage& message);
[[nodiscard]] Expected<PlanAckMessage> DecodePlanAck(std::string_view payload);
[[nodiscard]] std::string EncodeValidate(const ValidateMessage& message);
[[nodiscard]] Expected<ValidateMessage> DecodeValidate(std::string_view payload);
[[nodiscard]] std::string EncodeValidateAck(const ValidateAckMessage& message);
[[nodiscard]] Expected<ValidateAckMessage> DecodeValidateAck(std::string_view payload);
[[nodiscard]] std::string EncodeGetPlan(const GetPlanMessage& message);
[[nodiscard]] Expected<GetPlanMessage> DecodeGetPlan(std::string_view payload);
[[nodiscard]] std::string EncodeGetPlanAck(const GetPlanAckMessage& message);
[[nodiscard]] Expected<GetPlanAckMessage> DecodeGetPlanAck(std::string_view payload);
[[nodiscard]] std::string EncodeStoreList();
[[nodiscard]] std::string EncodeStoreListAck(const StoreListAckMessage& message);
[[nodiscard]] Expected<StoreListAckMessage> DecodeStoreListAck(std::string_view payload);
[[nodiscard]] std::string EncodeCancel(const CancelMessage& message);
[[nodiscard]] Expected<CancelMessage> DecodeCancel(std::string_view payload);
[[nodiscard]] std::string EncodeCancelAck(const CancelAckMessage& message);
[[nodiscard]] Expected<CancelAckMessage> DecodeCancelAck(std::string_view payload);
[[nodiscard]] std::string EncodeStats();
[[nodiscard]] std::string EncodeStatsAck(const StatsAckMessage& message);
[[nodiscard]] Expected<StatsAckMessage> DecodeStatsAck(std::string_view payload);
struct FailureMessage {
  StatusCode code = StatusCode::Internal;
  std::string detail;
};
[[nodiscard]] std::string EncodeFailure(const FailureMessage& message);
[[nodiscard]] Expected<FailureMessage> DecodeFailure(std::string_view payload);

// The one place a status is rendered into a frame, so that every rejection code
// reaches the caller unchanged.
[[nodiscard]] Frame MakeFailureFrame(std::uint64_t sequence, Epoch epoch_pin, const Status& status);

}  // namespace opp
