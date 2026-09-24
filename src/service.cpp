#include "opp/service.hpp"

#include <algorithm>
#include <atomic>
#include <thread>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "opp/fileio.hpp"
#include "opp/canonical.hpp"
#include "opp/limits.hpp"
#include "opp/planner.hpp"
#include "opp/request_io.hpp"
#include "opp/sha256.hpp"
#include "opp/snapshot_io.hpp"
#include "opp/version.hpp"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace opp {
namespace {


constexpr const char* kSnapshotFileName = "snapshot.oppsnap";
// How long the accept loop waits before re-checking its stop flag.
constexpr std::int64_t kAcceptPollMicros = 50000;
// Upper bound on how long a socket read may block before the stop flag is
// re-checked.
constexpr std::int64_t kReceiveTimeoutMicros = 200000;
constexpr const char* kIncarnationFileName = "incarnation.oppf";

#if defined(_WIN32)
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;

struct WinsockGuard {
  WinsockGuard() {
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
  }
  ~WinsockGuard() { WSACleanup(); }
};

void EnsureWinsock() {
  static WinsockGuard guard;
  (void)guard;
}
#else
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
void EnsureWinsock() {}
#endif

void CloseSocket(SocketHandle handle) {
  if (handle == kInvalidSocket) return;
#if defined(_WIN32)
  closesocket(handle);
#else
  close(handle);
#endif
}

void ShutdownSocket(SocketHandle handle) {
  if (handle == kInvalidSocket) return;
#if defined(_WIN32)
  shutdown(handle, SD_BOTH);
#else
  shutdown(handle, SHUT_RDWR);
#endif
}

bool WriteAll(SocketHandle handle, std::string_view bytes) {
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const int chunk = static_cast<int>(std::min<std::size_t>(bytes.size() - offset, 1u << 20));
#if defined(_WIN32)
    const int sent = send(handle, bytes.data() + offset, chunk, 0);
#else
    const int sent = static_cast<int>(send(handle, bytes.data() + offset, static_cast<std::size_t>(chunk), 0));
#endif
    if (sent <= 0) return false;
    offset += static_cast<std::size_t>(sent);
  }
  return true;
}

bool WouldBlock() {
#if defined(_WIN32)
  const int error = WSAGetLastError();
  return error == WSAETIMEDOUT || error == WSAEWOULDBLOCK;
#else
  return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

// Reads exactly count bytes. A receive timeout is not a failure: it is the
// chance to observe the stop flag, so the loop retries while the service is
// still running and gives up as soon as it is not.
bool ReadAll(SocketHandle handle, char* buffer, std::size_t count, const std::atomic<bool>* stop) {
  std::size_t offset = 0;
  while (offset < count) {
    const int chunk = static_cast<int>(std::min<std::size_t>(count - offset, 1u << 20));
#if defined(_WIN32)
    const int received = recv(handle, buffer + offset, chunk, 0);
#else
    const int received = static_cast<int>(recv(handle, buffer + offset, static_cast<std::size_t>(chunk), 0));
#endif
    if (received <= 0) {
      if (received < 0 && WouldBlock()) {
        if (stop != nullptr && stop->load(std::memory_order_acquire)) return false;
        continue;
      }
      return false;
    }
    offset += static_cast<std::size_t>(received);
  }
  return true;
}

constexpr std::size_t kFrameHeaderBytes = 4 + 4 + 4 + 8 + 8 + 4;

bool ReadFrame(SocketHandle handle, std::uint32_t max_frame_bytes, const std::atomic<bool>* stop, Frame* frame,
               Status* status) {
  char header[kFrameHeaderBytes];
  if (!ReadAll(handle, header, kFrameHeaderBytes, stop)) {
    *status = Failure(StatusCode::IoFailure, "connection closed while reading a frame header");
    return false;
  }
  const std::string_view header_view(header, kFrameHeaderBytes);
  ByteReader reader(header_view);
  const auto magic = reader.U32();
  if (!magic.ok()) {
    *status = magic.status();
    return false;
  }
  if (magic.value() != kFrameMagic) {
    *status = Failure(StatusCode::MalformedInput, "frame magic is not recognised");
    return false;
  }
  const auto version = reader.U32();
  if (!version.ok()) {
    *status = version.status();
    return false;
  }
  if (version.value() != kProtocolVersion) {
    *status = Failure(StatusCode::Unsupported, "transport revision is not supported by this runtime");
    return false;
  }
  const auto kind = reader.U32();
  const auto sequence = reader.U64();
  const auto epoch = reader.U64();
  const auto length = reader.U32();
  if (!kind.ok() || !sequence.ok() || !epoch.ok() || !length.ok()) {
    *status = Failure(StatusCode::MalformedInput, "frame header is truncated");
    return false;
  }
  if (length.value() > max_frame_bytes) {
    *status = Failure(StatusCode::LimitExceeded, "frame payload exceeds the permitted maximum size");
    return false;
  }
  std::string payload;
  payload.resize(static_cast<std::size_t>(length.value()) + 32u);
  if (!payload.empty() && !ReadAll(handle, payload.data(), payload.size(), stop)) {
    *status = Failure(StatusCode::IoFailure, "connection closed while reading a frame body");
    return false;
  }
  std::string whole(header, kFrameHeaderBytes);
  whole += payload;
  std::size_t consumed = 0;
  const auto decoded = DecodeFrame(whole, &consumed);
  if (!decoded.ok()) {
    *status = decoded.status();
    return false;
  }
  *frame = decoded.value();
  return true;
}

bool SendFrame(SocketHandle handle, const Frame& frame) {
  const std::string bytes = EncodeFrame(frame);
  return WriteAll(handle, bytes);
}

}  // namespace

IncarnationId GenerateIncarnationId() {
  IncarnationId id;
#if defined(_WIN32)
  HCRYPTPROV provider = 0;
  if (CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) != 0) {
    CryptGenRandom(provider, static_cast<DWORD>(id.bytes.size()), id.bytes.data());
    CryptReleaseContext(provider, 0);
  }
#else
  std::FILE* file = std::fopen("/dev/urandom", "rb");
  if (file != nullptr) {
    if (std::fread(id.bytes.data(), 1, id.bytes.size(), file) != id.bytes.size()) {
      id = IncarnationId{};
    }
    std::fclose(file);
  }
#endif
  return id;
}

std::uint64_t UnixMillisNow() {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

Status StateDirectoryLock::Acquire(const std::string& path) {
  if (held()) return Failure(StatusCode::Internal, "the state directory lock is already held");
#if defined(_WIN32)
  const std::wstring wide = std::filesystem::path(path).wstring();
  HANDLE handle = CreateFileW(wide.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    return Failure(StatusCode::Refused, "another service instance holds the state directory lock");
  }
  handle_ = handle;
  return OkStatus();
#else
  const int descriptor = open(path.c_str(), O_RDWR | O_CREAT, 0600);
  if (descriptor < 0) {
    return Failure(StatusCode::IoFailure, "cannot open the state directory lock file");
  }
  if (flock(descriptor, LOCK_EX | LOCK_NB) != 0) {
    close(descriptor);
    return Failure(StatusCode::Refused, "another service instance holds the state directory lock");
  }
  handle_ = reinterpret_cast<void*>(static_cast<intptr_t>(descriptor + 1));
  return OkStatus();
#endif
}

void StateDirectoryLock::Release() {
  if (!held()) return;
#if defined(_WIN32)
  CloseHandle(reinterpret_cast<HANDLE>(handle_));
#else
  const int descriptor = static_cast<int>(reinterpret_cast<intptr_t>(handle_)) - 1;
  flock(descriptor, LOCK_UN);
  close(descriptor);
#endif
  handle_ = nullptr;
}

StateDirectoryLock::~StateDirectoryLock() { Release(); }

Expected<IncarnationState> AdvanceIncarnation(const std::string& state_dir) {
  const Status directory = EnsureDirectory(state_dir);
  if (directory.failed()) return directory;

  IncarnationState state;
  state.incarnation = GenerateIncarnationId();
  state.started_unix_ms = UnixMillisNow();
  state.process_id = ProcessId();
  state.epoch_continuity = true;

  const std::string path = JoinPath(state_dir, kIncarnationFileName);
  Generation previous_epoch = 0;
  if (FileExists(path)) {
    const auto bytes = ReadFileBounded(path, 4096);
    bool parsed = false;
    if (bytes.ok()) {
      // The record is a line oriented file; parsing it as a single line would
      // silently read the wrong field and lose epoch continuity.
      const std::string& text = bytes.value();
      const std::string_view view(text);
      std::size_t cursor = 0;
      bool header_seen = false;
      while (cursor < text.size()) {
        const std::size_t newline = text.find('\n', cursor);
        std::string_view line =
            newline == std::string::npos ? view.substr(cursor) : view.substr(cursor, newline - cursor);
        cursor = newline == std::string::npos ? text.size() : newline + 1;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) continue;
        const auto tokens = SplitTokens(line);
        if (!tokens.ok()) break;
        const std::vector<std::string>& values = tokens.value();
        if (!header_seen) {
          if (values.size() != 2 || values[0] != "OPP-INCARNATION") break;
          header_seen = true;
          continue;
        }
        if (values[0] == "epoch") {
          if (values.size() != 2) break;
          const auto epoch = ParseU64(values[1]);
          if (!epoch.ok()) break;
          previous_epoch = epoch.value();
          parsed = true;
          break;
        }
      }
    }
    if (!parsed) {
      state.epoch_continuity = false;
      // A record that cannot be read is quarantined rather than deleted, so an
      // operator can still see what the previous incarnation published.
      const Status quarantined = RenameFile(path, path + ".unreadable");
      if (quarantined.failed()) {
        return Failure(StatusCode::IoFailure, "cannot quarantine an unreadable incarnation record");
      }
    }
  }

  if (previous_epoch >= std::numeric_limits<Epoch>::max() - 1) {
    return Failure(StatusCode::Exhausted, "the service epoch counter is exhausted");
  }
  state.epoch = previous_epoch + 1;

  std::string text;
  text += "OPP-INCARNATION 1\n";
  text += "incarnation ";
  text += state.incarnation.ToHex();
  text += "\n";
  text += "epoch " + FormatU64(state.epoch) + "\n";
  text += "pid " + FormatU64(state.process_id) + "\n";
  text += "started_unix_ms " + FormatU64(state.started_unix_ms) + "\n";
  const Status written = WriteFileAtomic(path, text);
  if (written.failed()) return written;
  return state;
}

Expected<std::unique_ptr<Service>> Service::Start(const ServiceOptions& options) {
  if (options.state_dir.empty()) {
    return Failure(StatusCode::InvalidArgument, "the service requires a state directory");
  }
  EnsureWinsock();
  std::unique_ptr<Service> service(new Service(options));

  std::error_code error;
  std::filesystem::create_directories(options.state_dir, error);
  if (error) {
    return Failure(StatusCode::IoFailure, "cannot create the state directory: " + error.message());
  }
  const Status locked = service->directory_lock_.Acquire(JoinPath(options.state_dir, "service.lock"));
  if (locked.failed()) return locked;

  const auto incarnation = AdvanceIncarnation(options.state_dir);
  if (!incarnation.ok()) return incarnation.status();
  service->incarnation_ = incarnation.value();

  // Bookkeeping vectors are pre-sized to the connection bound so that no worker
  // ever observes a reallocation of the tables that describe it.
  service->workers_.reserve(options.max_connections);
  service->active_connections_.reserve(options.max_connections);

  const std::string store_root = options.store_root.empty() ? options.state_dir : options.store_root;
  StoreOptions store_options;
  store_options.root = store_root;
  store_options.max_plans = options.max_stored_plans;
  auto store = PlanStore::Open(store_options);
  if (!store.ok()) return store.status();
  service->store_ = store.value();

  if (options.persist_snapshots) {
    const std::string snapshot_path = JoinPath(options.state_dir, kSnapshotFileName);
    if (FileExists(snapshot_path)) {
      const auto restored = LoadSnapshotFile(snapshot_path);
      if (restored.ok()) {
        TopologySnapshot snapshot = restored.value();
        snapshot.MarkRestored(service->incarnation_.incarnation, service->incarnation_.epoch);
        service->snapshot_ = std::make_shared<const TopologySnapshot>(std::move(snapshot));
        service->snapshot_fresh_ = false;
      }
    }
  }

  const SocketHandle listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (listener == kInvalidSocket) {
    return Failure(StatusCode::IoFailure, "cannot create the listening socket");
  }
  int reuse = 1;
#if defined(_WIN32)
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#else
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(options.port);
  if (options.bind_address.empty() || options.bind_address == "127.0.0.1") {
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  } else {
    if (inet_pton(AF_INET, options.bind_address.c_str(), &address.sin_addr) != 1) {
      CloseSocket(listener);
      return Failure(StatusCode::InvalidArgument, "the bind address must be a dotted-quad IPv4 address");
    }
  }
  if (bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    CloseSocket(listener);
    return Failure(StatusCode::IoFailure, "cannot bind the inspection service socket");
  }
  if (listen(listener, static_cast<int>(options.backlog)) != 0) {
    CloseSocket(listener);
    return Failure(StatusCode::IoFailure, "cannot listen on the inspection service socket");
  }
  sockaddr_in bound{};
#if defined(_WIN32)
  int bound_length = static_cast<int>(sizeof(bound));
#else
  socklen_t bound_length = sizeof(bound);
#endif
  if (getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &bound_length) == 0) {
    service->bound_port_ = ntohs(bound.sin_port);
  }
  service->listener_.store(reinterpret_cast<void*>(listener), std::memory_order_release);
  return service;
}

Service::~Service() {
  Shutdown();
  for (std::thread& worker : workers_) {
    if (worker.joinable()) worker.join();
  }
}

Status Service::Run() {
  const SocketHandle listener = reinterpret_cast<SocketHandle>(listener_.load(std::memory_order_acquire));
  if (listener == kInvalidSocket) {
    return Failure(StatusCode::Internal, "the service is not listening");
  }
  while (!stopping_.load(std::memory_order_acquire)) {
    // Wait for a connection with a bounded poll instead of blocking in accept().
    // Winsock does not guarantee that closing a listening socket wakes a thread
    // already blocked in accept(), so blocking there would make shutdown
    // unreliable; a poll keeps the stop flag authoritative.
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(listener, &readable);
    timeval poll_interval{};
    poll_interval.tv_sec = 0;
    poll_interval.tv_usec = kAcceptPollMicros;
#if defined(_WIN32)
    const int ready = select(0, &readable, nullptr, nullptr, &poll_interval);
#else
    const int ready = select(static_cast<int>(listener) + 1, &readable, nullptr, nullptr, &poll_interval);
#endif
    if (stopping_.load(std::memory_order_acquire)) break;
    if (ready <= 0) continue;

    sockaddr_in peer{};
#if defined(_WIN32)
    int peer_length = static_cast<int>(sizeof(peer));
#else
    socklen_t peer_length = sizeof(peer);
#endif
    const SocketHandle connection = accept(listener, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    if (connection == kInvalidSocket) {
      if (stopping_.load(std::memory_order_acquire)) break;
      continue;
    }
    {
      std::lock_guard<std::mutex> guard(mutex_);
      if (workers_.size() >= options_.max_connections) {
        FailureMessage message;
        message.code = StatusCode::Exhausted;
        message.detail = "the service has reached its connection bound";
        Frame frame;
        frame.kind = MessageKind::Failure;
        frame.payload = EncodeFailure(message);
        SendFrame(connection, frame);
        CloseSocket(connection);
        stats_.frames_rejected += 1;
        continue;
      }
      stats_.connections_accepted += 1;
      active_connections_.push_back(reinterpret_cast<void*>(connection));
      workers_.emplace_back([this, connection]() { ServeConnection(reinterpret_cast<void*>(connection)); });
    }
  }
  // The listener belongs to this loop; closing it here keeps every socket
  // operation on the owning thread.
  const SocketHandle owned = reinterpret_cast<SocketHandle>(listener_.exchange(nullptr, std::memory_order_acq_rel));
  if (owned != kInvalidSocket) CloseSocket(owned);
  for (std::thread& worker : workers_) {
    if (worker.joinable()) worker.join();
  }
  return OkStatus();
}

void Service::Shutdown() { StopConnections(nullptr); }

void Service::StopConnections(void* except) {
  // Shutdown is a flag, never a cross-thread socket operation. Closing or
  // shutting a socket down while another thread is blocked in select() or
  // recv() on it is not safe, so the listening socket is closed by the accept
  // loop that owns it and each connection worker notices the flag on its next
  // poll or receive timeout.
  (void)except;
  stopping_.store(true, std::memory_order_release);
}

void Service::ServeConnection(void* socket_handle) {
  const SocketHandle handle = reinterpret_cast<SocketHandle>(socket_handle);
  while (!stopping_.load(std::memory_order_acquire)) {
    // Bounded poll and bounded receive keep every wait short so that a worker
    // always returns and the accept loop can join it.
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(handle, &readable);
    timeval poll_interval{};
    poll_interval.tv_sec = 0;
    poll_interval.tv_usec = kAcceptPollMicros;
#if defined(_WIN32)
    const int ready = select(0, &readable, nullptr, nullptr, &poll_interval);
#else
    const int ready = select(static_cast<int>(handle) + 1, &readable, nullptr, nullptr, &poll_interval);
#endif
    if (stopping_.load(std::memory_order_acquire)) break;
    if (ready <= 0) continue;

    Frame frame;
    Status status;
    if (!ReadFrame(handle, options_.max_frame_bytes, &stopping_, &frame, &status)) {
      if (status.code != StatusCode::IoFailure) {
        SendFrame(handle, MakeFailureFrame(0, incarnation_.epoch, status));
        std::lock_guard<std::mutex> guard(mutex_);
        stats_.frames_rejected += 1;
      }
      break;
    }
    if (frame.kind == MessageKind::Shutdown) {
      // The reply is written before any teardown starts, so the caller always
      // learns that its request was accepted.
      Frame ack;
      ack.kind = MessageKind::ShutdownAck;
      ack.sequence = frame.sequence;
      ack.epoch_pin = incarnation_.epoch;
      {
        std::lock_guard<std::mutex> guard(mutex_);
        stats_.frames_handled += 1;
      }
      SendFrame(handle, ack);
      StopConnections(reinterpret_cast<void*>(handle));
      break;
    }
    const Frame response = HandleFrameFor(frame, reinterpret_cast<void*>(handle));
    if (response.kind == MessageKind::Failure) {
      std::lock_guard<std::mutex> guard(mutex_);
      stats_.frames_rejected += 1;
    } else {
      std::lock_guard<std::mutex> guard(mutex_);
      stats_.frames_handled += 1;
    }
    if (!SendFrame(handle, response)) break;
  }
  {
    std::lock_guard<std::mutex> guard(mutex_);
    const auto entry = std::find(active_connections_.begin(), active_connections_.end(),
                                 reinterpret_cast<void*>(handle));
    if (entry != active_connections_.end()) active_connections_.erase(entry);
  }
  CloseSocket(handle);
}

Frame Service::HandleFrame(const Frame& frame) { return HandleFrameFor(frame, nullptr); }

Frame Service::HandleFrameFor(const Frame& frame, void* caller) {
  const auto fenced = [&](const char* detail) {
    std::lock_guard<std::mutex> guard(mutex_);
    stats_.fenced_frames += 1;
    return MakeFailureFrame(frame.sequence, incarnation_.epoch,
                            Failure(StatusCode::Fenced, std::string(detail) + " (current epoch " +
                                                            FormatU64(incarnation_.epoch) + ")"));
  };
  if (frame.epoch_pin != 0 && frame.epoch_pin != incarnation_.epoch) {
    return fenced("the frame is pinned to an epoch this incarnation does not own");
  }

  const auto failure = [&](const Status& status) {
    return MakeFailureFrame(frame.sequence, incarnation_.epoch, status);
  };

  Frame response;
  response.sequence = frame.sequence;
  response.epoch_pin = incarnation_.epoch;

  switch (frame.kind) {
    case MessageKind::Hello: {
      const auto message = DecodeHello(frame.payload);
      if (!message.ok()) return failure(message.status());
      if (message.value().protocol_version != kProtocolVersion) {
        return failure(Failure(StatusCode::Unsupported, "client transport revision is not supported"));
      }
      HelloAckMessage ack;
      ack.protocol_version = kProtocolVersion;
      ack.library_version = VersionString();
      ack.incarnation = incarnation_.incarnation;
      ack.epoch = incarnation_.epoch;
      ack.epoch_continuity = incarnation_.epoch_continuity;
      {
        std::lock_guard<std::mutex> guard(mutex_);
        ack.has_snapshot = snapshot_ != nullptr;
        ack.snapshot_fresh = snapshot_fresh_;
        if (snapshot_ != nullptr) {
          ack.snapshot_id = snapshot_->id();
          ack.snapshot_generation = snapshot_->generation();
          ack.snapshot_digest = snapshot_->digest();
        }
      }
      response.kind = MessageKind::HelloAck;
      response.payload = EncodeHelloAck(ack);
      return response;
    }
    case MessageKind::Ingest: {
      const auto message = DecodeIngest(frame.payload);
      if (!message.ok()) return failure(message.status());
      const auto parsed = ParseSnapshotText(message.value().snapshot_text);
      if (!parsed.ok()) return failure(parsed.status());
      if (!(parsed.value().digest() == message.value().snapshot_digest)) {
        return failure(Failure(StatusCode::IntegrityFailure,
                               "the declared snapshot digest does not match the snapshot content"));
      }
      const std::string snapshot_path = JoinPath(options_.state_dir, kSnapshotFileName);
      if (options_.persist_snapshots) {
        const Status written = SaveSnapshotFile(snapshot_path, parsed.value());
        if (written.failed()) return failure(written);
      }
      {
        std::lock_guard<std::mutex> guard(mutex_);
        snapshot_ = std::make_shared<const TopologySnapshot>(parsed.value());
        snapshot_fresh_ = true;
        stats_.snapshots_ingested += 1;
      }
      IngestAckMessage ack;
      ack.snapshot_id = parsed.value().id();
      ack.generation = parsed.value().generation();
      ack.snapshot_digest = parsed.value().digest();
      response.kind = MessageKind::IngestAck;
      response.payload = EncodeIngestAck(ack);
      return response;
    }
    case MessageKind::Plan: {
      // The asynchronous path never reaches here: plan requests are handed to
      // the planning thread. This branch serves the in-process API.
      const auto message = DecodePlan(frame.payload);
      if (!message.ok()) return failure(message.status());
      const auto request = ParseRequestText(message.value().request_text);
      if (!request.ok()) return failure(request.status());

      std::shared_ptr<const TopologySnapshot> snapshot;
      {
        std::lock_guard<std::mutex> guard(mutex_);
        snapshot = snapshot_;
        stats_.active_requests += 1;
      }
      PlanningResult result;
      if (snapshot == nullptr) {
        result.outcome = PlanOutcome::Indeterminate;
        result.status = Failure(StatusCode::NotFound,
                                "no topology snapshot has been ingested by this incarnation");
        result.limitations = kLimitationStaleEvidence;
        result.request_digest = ComputeRequestDigest(request.value());
        result.Seal();
      } else {
        PlannerOptions planner_options;
        planner_options.expansion_ceiling = options_.expansion_ceiling;
        const Planner planner(planner_options);
        result = planner.Plan(*snapshot, request.value(), CancelToken());
      }

      bool stored = true;
      if (result.outcome == PlanOutcome::Feasible) {
        for (const PlanArtifact& plan : result.candidates) {
          const Status put = store_->Put(plan);
          if (put.failed()) stored = false;
        }
      }
      {
        std::lock_guard<std::mutex> guard(mutex_);
        stats_.active_requests -= 1;
        if (result.outcome == PlanOutcome::Cancelled) {
          stats_.plans_cancelled += 1;
        } else if (result.outcome == PlanOutcome::Feasible) {
          stats_.plans_computed += 1;
          if (!stored) stats_.plans_rejected += 1;
        } else {
          stats_.plans_rejected += 1;
        }
      }
      PlanAckMessage ack;
      ack.result_text = result.CanonicalBytes();
      response.kind = MessageKind::PlanAck;
      response.payload = EncodePlanAck(ack);
      return response;
    }
    case MessageKind::Validate: {
      const auto message = DecodeValidate(frame.payload);
      if (!message.ok()) return failure(message.status());
      const auto plan = ParsePlanArtifact(message.value().plan_text);
      if (!plan.ok()) return failure(plan.status());
      std::shared_ptr<const TopologySnapshot> snapshot;
      {
        std::lock_guard<std::mutex> guard(mutex_);
        snapshot = snapshot_;
      }
      ValidateAckMessage ack;
      if (snapshot == nullptr) {
        ack.validity = PlanValidity::MissingEvidence;
        ack.report_text = "no topology snapshot has been ingested by this incarnation";
      } else {
        const ValidationReport report = ValidatePlanBindings(plan.value(), *snapshot, message.value().policy);
        ack.validity = report.validity;
        ack.report_text = report.ExplainText();
      }
      response.kind = MessageKind::ValidateAck;
      response.payload = EncodeValidateAck(ack);
      return response;
    }
    case MessageKind::GetPlan: {
      const auto message = DecodeGetPlan(frame.payload);
      if (!message.ok()) return failure(message.status());
      const auto plan = store_->Get(message.value().digest);
      if (!plan.ok()) return failure(plan.status());
      GetPlanAckMessage ack;
      ack.digest = plan.value().digest;
      ack.plan_text = plan.value().CanonicalBytes();
      response.kind = MessageKind::GetPlanAck;
      response.payload = EncodeGetPlanAck(ack);
      return response;
    }
    case MessageKind::StoreList: {
      std::vector<StoreEntry> entries;
      std::vector<std::string> rejected;
      const Status status = store_->List(&entries, &rejected);
      if (status.failed()) return failure(status);
      StoreListAckMessage ack;
      for (const StoreEntry& entry : entries) ack.digests.push_back(entry.digest);
      ack.rejected_files = std::move(rejected);
      response.kind = MessageKind::StoreListAck;
      response.payload = EncodeStoreListAck(ack);
      return response;
    }
    case MessageKind::Cancel: {
      const auto message = DecodeCancel(frame.payload);
      if (!message.ok()) return failure(message.status());
      CancelAckMessage ack;
      ack.found = false;
      {
        std::lock_guard<std::mutex> guard(mutex_);
        if (message.value().cancel_token == 0) {
          for (auto& entry : cancellations_) entry.second.Request();
          ack.found = !cancellations_.empty();
        } else {
          const auto found = cancellations_.find(message.value().cancel_token);
          if (found != cancellations_.end()) {
            found->second.Request();
            ack.found = true;
          }
        }
      }
      response.kind = MessageKind::CancelAck;
      response.payload = EncodeCancelAck(ack);
      return response;
    }
    case MessageKind::Stats: {
      StatsAckMessage ack;
      ack.incarnation = incarnation_.incarnation;
      ack.epoch = incarnation_.epoch;
      {
        std::lock_guard<std::mutex> guard(mutex_);
        ack.connections_accepted = stats_.connections_accepted;
        ack.frames_handled = stats_.frames_handled;
        ack.frames_rejected = stats_.frames_rejected;
        ack.snapshots_ingested = stats_.snapshots_ingested;
        ack.plans_computed = stats_.plans_computed;
        ack.plans_rejected = stats_.plans_rejected;
        ack.plans_cancelled = stats_.plans_cancelled;
        ack.active_requests = stats_.active_requests;
        ack.fenced_frames = stats_.fenced_frames;
      }
      ack.stored_plans = store_->Count();
      response.kind = MessageKind::StatsAck;
      response.payload = EncodeStatsAck(ack);
      return response;
    }
    case MessageKind::Shutdown: {
      response.kind = MessageKind::ShutdownAck;
      response.payload.clear();
      StopConnections(caller);
      return response;
    }
    default:
      return failure(Failure(StatusCode::InvalidArgument, "the frame is not a request this service handles"));
  }
}

ServiceStats Service::Stats() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return stats_;
}

ServiceClient::~ServiceClient() {
  CloseSocket(reinterpret_cast<SocketHandle>(socket_handle_));
}

Expected<std::unique_ptr<ServiceClient>> ServiceClient::Connect(const Options& options) {
  EnsureWinsock();
  if (options.port == 0) {
    return Failure(StatusCode::InvalidArgument, "a client must name the port to connect to");
  }
  std::unique_ptr<ServiceClient> client(new ServiceClient(options));
  const SocketHandle handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == kInvalidSocket) {
    return Failure(StatusCode::IoFailure, "cannot create a client socket");
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(options.port);
  if (options.host.empty() || options.host == "127.0.0.1") {
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  } else if (inet_pton(AF_INET, options.host.c_str(), &address.sin_addr) != 1) {
    CloseSocket(handle);
    return Failure(StatusCode::InvalidArgument, "the client host must be a dotted-quad IPv4 address");
  }
  if (connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    CloseSocket(handle);
    return Failure(StatusCode::IoFailure, "cannot connect to the inspection service");
  }
  client->socket_handle_ = reinterpret_cast<void*>(handle);
  return client;
}

Status ServiceClient::SendFrame(const Frame& frame) {
  const SocketHandle handle = reinterpret_cast<SocketHandle>(socket_handle_);
  if (handle == kInvalidSocket) {
    return Failure(StatusCode::Internal, "the client socket is not connected");
  }
  if (!opp::WriteAll(handle, EncodeFrame(frame))) {
    return Failure(StatusCode::IoFailure, "cannot send a frame to the inspection service");
  }
  return OkStatus();
}

Expected<Frame> ServiceClient::Exchange(MessageKind kind, const std::string& payload) {
  Frame frame;
  frame.kind = kind;
  frame.sequence = ++sequence_;
  frame.epoch_pin = epoch_pin_;
  frame.payload = payload;
  const Status sent = SendFrame(frame);
  if (sent.failed()) return sent;

  const SocketHandle handle = reinterpret_cast<SocketHandle>(socket_handle_);
  Frame response;
  Status status;
  if (!ReadFrame(handle, options_.max_frame_bytes, nullptr, &response, &status)) {
    return status;
  }
  if (response.kind == MessageKind::Failure) {
    const auto message = DecodeFailure(response.payload);
    if (!message.ok()) return message.status();
    return Failure(message.value().code, message.value().detail);
  }
  return response;
}

Expected<HelloAckMessage> ServiceClient::Hello(std::string_view client_name) {
  HelloMessage message;
  message.protocol_version = kProtocolVersion;
  message.client_name = std::string(client_name);
  const auto response = Exchange(MessageKind::Hello, EncodeHello(message));
  if (!response.ok()) return response.status();
  if (response.value().kind != MessageKind::HelloAck) {
    return Failure(StatusCode::Internal, "the service answered a hello with an unexpected message");
  }
  return DecodeHelloAck(response.value().payload);
}

Expected<IngestAckMessage> ServiceClient::Ingest(const TopologySnapshot& snapshot) {
  IngestMessage message;
  message.snapshot_digest = snapshot.digest();
  message.snapshot_text = SnapshotToText(snapshot);
  const auto response = Exchange(MessageKind::Ingest, EncodeIngest(message));
  if (!response.ok()) return response.status();
  if (response.value().kind != MessageKind::IngestAck) {
    return Failure(StatusCode::Internal, "the service answered an ingest with an unexpected message");
  }
  return DecodeIngestAck(response.value().payload);
}

Expected<PlanningResult> ServiceClient::Plan(const PlanningRequest& request, std::uint64_t cancel_token) {
  PlanMessage message;
  message.cancel_token = cancel_token;
  message.request_text = RequestToText(request);
  const auto response = Exchange(MessageKind::Plan, EncodePlan(message));
  if (!response.ok()) return response.status();
  if (response.value().kind != MessageKind::PlanAck) {
    return Failure(StatusCode::Internal, "the service answered a plan request with an unexpected message");
  }
  const auto ack = DecodePlanAck(response.value().payload);
  if (!ack.ok()) return ack.status();
  return ParseResultText(ack.value().result_text);
}

Expected<ValidationReport> ServiceClient::Validate(const PlanArtifact& plan, const ValidationPolicy& policy) {
  ValidateMessage message;
  message.policy = policy;
  message.plan_text = plan.CanonicalBytes();
  const auto response = Exchange(MessageKind::Validate, EncodeValidate(message));
  if (!response.ok()) return response.status();
  if (response.value().kind != MessageKind::ValidateAck) {
    return Failure(StatusCode::Internal, "the service answered a validation with an unexpected message");
  }
  const auto ack = DecodeValidateAck(response.value().payload);
  if (!ack.ok()) return ack.status();
  ValidationReport report;
  report.validity = ack.value().validity;
  report.status = ack.value().validity == PlanValidity::Valid
                      ? OkStatus()
                      : Failure(StatusCode::Stale, ack.value().report_text);
  return report;
}

Expected<PlanArtifact> ServiceClient::GetPlan(const Digest256& digest) {
  GetPlanMessage message;
  message.digest = digest;
  const auto response = Exchange(MessageKind::GetPlan, EncodeGetPlan(message));
  if (!response.ok()) return response.status();
  if (response.value().kind != MessageKind::GetPlanAck) {
    return Failure(StatusCode::Internal, "the service answered a fetch with an unexpected message");
  }
  const auto ack = DecodeGetPlanAck(response.value().payload);
  if (!ack.ok()) return ack.status();
  return ParsePlanArtifact(ack.value().plan_text);
}

Expected<StoreListAckMessage> ServiceClient::StoreList() {
  const auto response = Exchange(MessageKind::StoreList, EncodeStoreList());
  if (!response.ok()) return response.status();
  if (response.value().kind != MessageKind::StoreListAck) {
    return Failure(StatusCode::Internal, "the service answered a listing with an unexpected message");
  }
  return DecodeStoreListAck(response.value().payload);
}

Expected<CancelAckMessage> ServiceClient::Cancel(std::uint64_t cancel_token) {
  CancelMessage message;
  message.cancel_token = cancel_token;
  const auto response = Exchange(MessageKind::Cancel, EncodeCancel(message));
  if (!response.ok()) return response.status();
  if (response.value().kind != MessageKind::CancelAck) {
    return Failure(StatusCode::Internal, "the service answered a cancellation with an unexpected message");
  }
  return DecodeCancelAck(response.value().payload);
}

Expected<StatsAckMessage> ServiceClient::Stats() {
  const auto response = Exchange(MessageKind::Stats, EncodeStats());
  if (!response.ok()) return response.status();
  if (response.value().kind != MessageKind::StatsAck) {
    return Failure(StatusCode::Internal, "the service answered a statistics request with an unexpected message");
  }
  return DecodeStatsAck(response.value().payload);
}

Status ServiceClient::Shutdown() {
  const auto response = Exchange(MessageKind::Shutdown, std::string());
  if (!response.ok()) return response.status();
  if (response.value().kind != MessageKind::ShutdownAck) {
    return Failure(StatusCode::Internal, "the service answered a shutdown with an unexpected message");
  }
  return OkStatus();
}

}  // namespace opp
