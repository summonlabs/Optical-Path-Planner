#include "opp/proto.hpp"

#include <string>
#include <utility>

#include "opp/canonical.hpp"
#include "opp/sha256.hpp"

namespace opp {
namespace {

constexpr std::size_t kFrameHeaderBytes = 4 + 4 + 4 + 8 + 8 + 4;

std::string EncodeFrameBody(MessageKind kind, std::uint64_t sequence, Epoch epoch_pin, std::string_view payload) {
  ByteWriter writer;
  writer.U32(kFrameMagic);
  writer.U32(kProtocolVersion);
  writer.U32(static_cast<std::uint32_t>(kind));
  writer.U64(sequence);
  writer.U64(epoch_pin);
  writer.U32(static_cast<std::uint32_t>(payload.size()));
  std::string body = writer.Take();
  body.append(payload);
  return body;
}

}  // namespace

const char* MessageKindName(MessageKind kind) noexcept {
  switch (kind) {
    case MessageKind::Hello:
      return "HELLO";
    case MessageKind::HelloAck:
      return "HELLO_ACK";
    case MessageKind::Ingest:
      return "INGEST";
    case MessageKind::IngestAck:
      return "INGEST_ACK";
    case MessageKind::Plan:
      return "PLAN";
    case MessageKind::PlanAck:
      return "PLAN_ACK";
    case MessageKind::Validate:
      return "VALIDATE";
    case MessageKind::ValidateAck:
      return "VALIDATE_ACK";
    case MessageKind::GetPlan:
      return "GET_PLAN";
    case MessageKind::GetPlanAck:
      return "GET_PLAN_ACK";
    case MessageKind::StoreList:
      return "STORE_LIST";
    case MessageKind::StoreListAck:
      return "STORE_LIST_ACK";
    case MessageKind::Cancel:
      return "CANCEL";
    case MessageKind::CancelAck:
      return "CANCEL_ACK";
    case MessageKind::Stats:
      return "STATS";
    case MessageKind::StatsAck:
      return "STATS_ACK";
    case MessageKind::Shutdown:
      return "SHUTDOWN";
    case MessageKind::ShutdownAck:
      return "SHUTDOWN_ACK";
    case MessageKind::Failure:
      return "FAILURE";
  }
  return "UNKNOWN";
}

bool Frame::IsRequest() const noexcept {
  switch (kind) {
    case MessageKind::Hello:
    case MessageKind::Ingest:
    case MessageKind::Plan:
    case MessageKind::Validate:
    case MessageKind::GetPlan:
    case MessageKind::StoreList:
    case MessageKind::Cancel:
    case MessageKind::Stats:
    case MessageKind::Shutdown:
      return true;
    default:
      return false;
  }
}

std::string EncodeFrame(const Frame& frame) {
  std::string body = EncodeFrameBody(frame.kind, frame.sequence, frame.epoch_pin, frame.payload);
  Sha256 hasher;
  hasher.Update(body);
  const Digest256 checksum = hasher.Finalize();
  body.append(reinterpret_cast<const char*>(checksum.bytes.data()), checksum.bytes.size());
  return body;
}

Expected<std::size_t> FrameSize(std::string_view bytes) {
  if (bytes.size() < kFrameHeaderBytes) {
    return Failure(StatusCode::NotFound, "frame header is incomplete");
  }
  ByteReader reader(bytes.substr(0, kFrameHeaderBytes));
  const auto magic = reader.U32();
  if (!magic.ok()) return magic.status();
  if (magic.value() != kFrameMagic) {
    return Failure(StatusCode::MalformedInput, "frame magic is not recognised");
  }
  const auto version = reader.U32();
  if (!version.ok()) return version.status();
  const auto kind = reader.U32();
  if (!kind.ok()) return kind.status();
  const auto sequence = reader.U64();
  if (!sequence.ok()) return sequence.status();
  const auto epoch = reader.U64();
  if (!epoch.ok()) return epoch.status();
  const auto length = reader.U32();
  if (!length.ok()) return length.status();
  if (length.value() > kMaxFrameBytes) {
    return Failure(StatusCode::LimitExceeded, "frame payload exceeds the permitted maximum size");
  }
  const std::uint64_t total = static_cast<std::uint64_t>(kFrameHeaderBytes) + length.value() + 32u;
  if (static_cast<std::uint64_t>(bytes.size()) < total) {
    return Failure(StatusCode::NotFound, "frame body is incomplete");
  }
  return static_cast<std::size_t>(total);
}

Expected<Frame> DecodeFrame(std::string_view bytes, std::size_t* consumed) {
  const auto size = FrameSize(bytes);
  if (!size.ok()) return size.status();
  const std::size_t total = size.value();
  Sha256 hasher;
  hasher.Update(bytes.substr(0, total - 32));
  const Digest256 checksum = hasher.Finalize();
  const std::string_view trailer = bytes.substr(total - 32, 32);
  if (std::string_view(reinterpret_cast<const char*>(checksum.bytes.data()), 32) != trailer) {
    return Failure(StatusCode::IntegrityFailure, "frame checksum does not match its content");
  }

  ByteReader reader(bytes.substr(0, kFrameHeaderBytes));
  const auto magic = reader.U32();
  if (!magic.ok()) return magic.status();
  const auto version = reader.U32();
  if (!version.ok()) return version.status();
  if (version.value() != kProtocolVersion) {
    return Failure(StatusCode::Unsupported, "transport revision is not supported by this runtime");
  }
  const auto kind = reader.U32();
  if (!kind.ok()) return kind.status();
  const auto sequence = reader.U64();
  if (!sequence.ok()) return sequence.status();
  const auto epoch = reader.U64();
  if (!epoch.ok()) return epoch.status();
  const auto length = reader.U32();
  if (!length.ok()) return length.status();

  Frame frame;
  frame.kind = static_cast<MessageKind>(kind.value());
  frame.sequence = sequence.value();
  frame.epoch_pin = epoch.value();
  frame.payload = std::string(bytes.substr(kFrameHeaderBytes, length.value()));
  if (consumed != nullptr) *consumed = total;
  return frame;
}

Frame MakeFailureFrame(std::uint64_t sequence, Epoch epoch_pin, const Status& status) {
  FailureMessage message;
  message.code = status.code;
  message.detail = status.detail;
  Frame frame;
  frame.kind = MessageKind::Failure;
  frame.sequence = sequence;
  frame.epoch_pin = epoch_pin;
  frame.payload = EncodeFailure(message);
  return frame;
}

std::string EncodeHello(const HelloMessage& message) {
  ByteWriter writer;
  writer.U32(message.protocol_version);
  writer.Text(message.client_name);
  return writer.Take();
}

Expected<HelloMessage> DecodeHello(std::string_view payload) {
  ByteReader reader(payload);
  HelloMessage message;
  auto version = reader.U32();
  if (!version.ok()) return version.status();
  message.protocol_version = version.value();
  auto name = reader.Text();
  if (!name.ok()) return name.status();
  message.client_name = name.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodeHelloAck(const HelloAckMessage& message) {
  ByteWriter writer;
  writer.U32(message.protocol_version);
  writer.Text(message.library_version);
  writer.Incarnation(message.incarnation);
  writer.U64(message.epoch);
  writer.Bool(message.epoch_continuity);
  writer.Bool(message.has_snapshot);
  writer.Bool(message.snapshot_fresh);
  writer.Text(message.snapshot_id.str());
  writer.U64(message.snapshot_generation);
  writer.Digest(message.snapshot_digest);
  return writer.Take();
}

Expected<HelloAckMessage> DecodeHelloAck(std::string_view payload) {
  ByteReader reader(payload);
  HelloAckMessage message;
  auto version = reader.U32();
  if (!version.ok()) return version.status();
  message.protocol_version = version.value();
  auto library = reader.Text();
  if (!library.ok()) return library.status();
  message.library_version = library.value();
  auto incarnation = reader.Incarnation();
  if (!incarnation.ok()) return incarnation.status();
  message.incarnation = incarnation.value();
  auto epoch = reader.U64();
  if (!epoch.ok()) return epoch.status();
  message.epoch = epoch.value();
  auto continuity = reader.Bool();
  if (!continuity.ok()) return continuity.status();
  message.epoch_continuity = continuity.value();
  auto has_snapshot = reader.Bool();
  if (!has_snapshot.ok()) return has_snapshot.status();
  message.has_snapshot = has_snapshot.value();
  auto fresh = reader.Bool();
  if (!fresh.ok()) return fresh.status();
  message.snapshot_fresh = fresh.value();
  auto id = reader.Text();
  if (!id.ok()) return id.status();
  auto snapshot_id = SnapshotId::Parse(id.value());
  if (!snapshot_id.ok() && !id.value().empty()) return snapshot_id.status();
  message.snapshot_id = id.value().empty() ? SnapshotId{} : snapshot_id.value();
  auto generation = reader.U64();
  if (!generation.ok()) return generation.status();
  message.snapshot_generation = generation.value();
  auto digest = reader.Digest();
  if (!digest.ok()) return digest.status();
  message.snapshot_digest = digest.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodeIngest(const IngestMessage& message) {
  ByteWriter writer;
  writer.Digest(message.snapshot_digest);
  writer.Bytes(message.snapshot_text);
  return writer.Take();
}

Expected<IngestMessage> DecodeIngest(std::string_view payload) {
  ByteReader reader(payload);
  IngestMessage message;
  auto digest = reader.Digest();
  if (!digest.ok()) return digest.status();
  message.snapshot_digest = digest.value();
  auto text = reader.Bytes();
  if (!text.ok()) return text.status();
  message.snapshot_text = text.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodeIngestAck(const IngestAckMessage& message) {
  ByteWriter writer;
  writer.Text(message.snapshot_id.str());
  writer.U64(message.generation);
  writer.Digest(message.snapshot_digest);
  return writer.Take();
}

Expected<IngestAckMessage> DecodeIngestAck(std::string_view payload) {
  ByteReader reader(payload);
  IngestAckMessage message;
  auto id = reader.Text();
  if (!id.ok()) return id.status();
  auto snapshot_id = SnapshotId::Parse(id.value());
  if (!snapshot_id.ok()) return snapshot_id.status();
  message.snapshot_id = snapshot_id.value();
  auto generation = reader.U64();
  if (!generation.ok()) return generation.status();
  message.generation = generation.value();
  auto digest = reader.Digest();
  if (!digest.ok()) return digest.status();
  message.snapshot_digest = digest.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodePlan(const PlanMessage& message) {
  ByteWriter writer;
  writer.U64(message.cancel_token);
  writer.Bytes(message.request_text);
  return writer.Take();
}

Expected<PlanMessage> DecodePlan(std::string_view payload) {
  ByteReader reader(payload);
  PlanMessage message;
  auto token = reader.U64();
  if (!token.ok()) return token.status();
  message.cancel_token = token.value();
  auto text = reader.Bytes();
  if (!text.ok()) return text.status();
  message.request_text = text.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodePlanAck(const PlanAckMessage& message) {
  ByteWriter writer;
  writer.Bytes(message.result_text);
  return writer.Take();
}

Expected<PlanAckMessage> DecodePlanAck(std::string_view payload) {
  ByteReader reader(payload);
  PlanAckMessage message;
  auto text = reader.Bytes();
  if (!text.ok()) return text.status();
  message.result_text = text.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodeValidate(const ValidateMessage& message) {
  ByteWriter writer;
  writer.Bool(message.policy.accept_restored_evidence);
  writer.Bool(message.policy.revalidate_on_mismatch);
  writer.Bytes(message.plan_text);
  return writer.Take();
}

Expected<ValidateMessage> DecodeValidate(std::string_view payload) {
  ByteReader reader(payload);
  ValidateMessage message;
  auto accept = reader.Bool();
  if (!accept.ok()) return accept.status();
  message.policy.accept_restored_evidence = accept.value();
  auto revalidate = reader.Bool();
  if (!revalidate.ok()) return revalidate.status();
  message.policy.revalidate_on_mismatch = revalidate.value();
  auto text = reader.Bytes();
  if (!text.ok()) return text.status();
  message.plan_text = text.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodeValidateAck(const ValidateAckMessage& message) {
  ByteWriter writer;
  writer.U32(static_cast<std::uint32_t>(message.validity));
  writer.Text(message.report_text);
  return writer.Take();
}

Expected<ValidateAckMessage> DecodeValidateAck(std::string_view payload) {
  ByteReader reader(payload);
  ValidateAckMessage message;
  auto validity = reader.U32();
  if (!validity.ok()) return validity.status();
  if (validity.value() > static_cast<std::uint32_t>(PlanValidity::NotFresh)) {
    return Failure(StatusCode::MalformedInput, "validation validity value is not recognised");
  }
  message.validity = static_cast<PlanValidity>(validity.value());
  auto text = reader.Text();
  if (!text.ok()) return text.status();
  message.report_text = text.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodeGetPlan(const GetPlanMessage& message) {
  ByteWriter writer;
  writer.Digest(message.digest);
  return writer.Take();
}

Expected<GetPlanMessage> DecodeGetPlan(std::string_view payload) {
  ByteReader reader(payload);
  GetPlanMessage message;
  auto digest = reader.Digest();
  if (!digest.ok()) return digest.status();
  message.digest = digest.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodeGetPlanAck(const GetPlanAckMessage& message) {
  ByteWriter writer;
  writer.Digest(message.digest);
  writer.Bytes(message.plan_text);
  return writer.Take();
}

Expected<GetPlanAckMessage> DecodeGetPlanAck(std::string_view payload) {
  ByteReader reader(payload);
  GetPlanAckMessage message;
  auto digest = reader.Digest();
  if (!digest.ok()) return digest.status();
  message.digest = digest.value();
  auto text = reader.Bytes();
  if (!text.ok()) return text.status();
  message.plan_text = text.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodeStoreList() { return std::string(); }

std::string EncodeStoreListAck(const StoreListAckMessage& message) {
  ByteWriter writer;
  writer.U32(static_cast<std::uint32_t>(message.digests.size()));
  for (const Digest256& digest : message.digests) writer.Digest(digest);
  writer.U32(static_cast<std::uint32_t>(message.rejected_files.size()));
  for (const std::string& name : message.rejected_files) writer.Text(name);
  return writer.Take();
}

Expected<StoreListAckMessage> DecodeStoreListAck(std::string_view payload) {
  ByteReader reader(payload);
  StoreListAckMessage message;
  auto count = reader.U32();
  if (!count.ok()) return count.status();
  if (count.value() > kMaxStoredPlans) {
    return Failure(StatusCode::LimitExceeded, "store listing exceeds the permitted number of entries");
  }
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    auto digest = reader.Digest();
    if (!digest.ok()) return digest.status();
    message.digests.push_back(digest.value());
  }
  auto rejected = reader.U32();
  if (!rejected.ok()) return rejected.status();
  if (rejected.value() > kMaxStoredPlans) {
    return Failure(StatusCode::LimitExceeded, "store rejection list exceeds the permitted number of entries");
  }
  for (std::uint32_t i = 0; i < rejected.value(); ++i) {
    auto name = reader.Text();
    if (!name.ok()) return name.status();
    message.rejected_files.push_back(name.value());
  }
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodeCancel(const CancelMessage& message) {
  ByteWriter writer;
  writer.U64(message.cancel_token);
  return writer.Take();
}

Expected<CancelMessage> DecodeCancel(std::string_view payload) {
  ByteReader reader(payload);
  CancelMessage message;
  auto token = reader.U64();
  if (!token.ok()) return token.status();
  message.cancel_token = token.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodeCancelAck(const CancelAckMessage& message) {
  ByteWriter writer;
  writer.Bool(message.found);
  return writer.Take();
}

Expected<CancelAckMessage> DecodeCancelAck(std::string_view payload) {
  ByteReader reader(payload);
  CancelAckMessage message;
  auto found = reader.Bool();
  if (!found.ok()) return found.status();
  message.found = found.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodeStats() { return std::string(); }

std::string EncodeStatsAck(const StatsAckMessage& message) {
  ByteWriter writer;
  writer.Incarnation(message.incarnation);
  writer.U64(message.epoch);
  writer.U64(message.connections_accepted);
  writer.U64(message.frames_handled);
  writer.U64(message.frames_rejected);
  writer.U64(message.snapshots_ingested);
  writer.U64(message.plans_computed);
  writer.U64(message.plans_rejected);
  writer.U64(message.plans_cancelled);
  writer.U64(message.active_requests);
  writer.U64(message.stored_plans);
  writer.U64(message.fenced_frames);
  return writer.Take();
}

Expected<StatsAckMessage> DecodeStatsAck(std::string_view payload) {
  ByteReader reader(payload);
  StatsAckMessage message;
  auto incarnation = reader.Incarnation();
  if (!incarnation.ok()) return incarnation.status();
  message.incarnation = incarnation.value();
  auto epoch = reader.U64();
  if (!epoch.ok()) return epoch.status();
  message.epoch = epoch.value();
  const auto read = [&reader](std::uint64_t* out) -> Status {
    auto value = reader.U64();
    if (!value.ok()) return value.status();
    *out = value.value();
    return OkStatus();
  };
  Status status = read(&message.connections_accepted);
  if (status.failed()) return status;
  status = read(&message.frames_handled);
  if (status.failed()) return status;
  status = read(&message.frames_rejected);
  if (status.failed()) return status;
  status = read(&message.snapshots_ingested);
  if (status.failed()) return status;
  status = read(&message.plans_computed);
  if (status.failed()) return status;
  status = read(&message.plans_rejected);
  if (status.failed()) return status;
  status = read(&message.plans_cancelled);
  if (status.failed()) return status;
  status = read(&message.active_requests);
  if (status.failed()) return status;
  status = read(&message.stored_plans);
  if (status.failed()) return status;
  status = read(&message.fenced_frames);
  if (status.failed()) return status;
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

std::string EncodeFailure(const FailureMessage& message) {
  ByteWriter writer;
  writer.U32(static_cast<std::uint32_t>(message.code));
  writer.Text(message.detail);
  return writer.Take();
}

Expected<FailureMessage> DecodeFailure(std::string_view payload) {
  ByteReader reader(payload);
  FailureMessage message;
  auto code = reader.U32();
  if (!code.ok()) return code.status();
  message.code = static_cast<StatusCode>(code.value());
  auto detail = reader.Text();
  if (!detail.ok()) return detail.status();
  message.detail = detail.value();
  const Status end = reader.ExpectEnd();
  if (end.failed()) return end;
  return message;
}

}  // namespace opp
