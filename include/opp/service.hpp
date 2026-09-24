#pragma once

// Inspection service and its client.
//
// The service is the only component that owns a stateful lifetime. It holds at
// most one sealed snapshot, an immutable plan store and an incarnation/epoch
// pair. Restarting the process produces a new incarnation with a strictly higher
// epoch: frames pinned to an older epoch are fenced, and a snapshot that was
// restored from disk is never presented as fresh.
//
// Loopback TCP only. The transport is unauthenticated and unencrypted; it is an
// inspection surface, not an authority boundary.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "opp/ids.hpp"
#include "opp/plan.hpp"
#include "opp/planner.hpp"
#include "opp/proto.hpp"
#include "opp/request.hpp"
#include "opp/result.hpp"
#include "opp/status.hpp"
#include "opp/store.hpp"
#include "opp/topology.hpp"

namespace opp {

// Exclusive advisory lock on a state directory. The operating system releases it
// when the owning process ends, including on abnormal termination, so a restart
// after a kill is never blocked by a stale lock file.
class StateDirectoryLock {
 public:
  StateDirectoryLock() = default;
  ~StateDirectoryLock();
  StateDirectoryLock(const StateDirectoryLock&) = delete;
  StateDirectoryLock& operator=(const StateDirectoryLock&) = delete;

  [[nodiscard]] Status Acquire(const std::string& path);
  void Release();
  [[nodiscard]] bool held() const noexcept { return handle_ != nullptr; }

 private:
  void* handle_ = nullptr;
};

struct IncarnationState {
  IncarnationId incarnation{};
  Epoch epoch = 0;
  // False when the previous incarnation record could not be read, so epoch
  // continuity could not be established.
  bool epoch_continuity = true;
  std::uint64_t started_unix_ms = 0;
  std::uint64_t process_id = 0;
};

// Reads, increments and rewrites the incarnation record in a state directory.
[[nodiscard]] Expected<IncarnationState> AdvanceIncarnation(const std::string& state_dir);

struct ServiceOptions {
  std::string state_dir;
  std::string store_root;
  std::string bind_address = kServiceBindAddress;
  std::uint16_t port = 0;
  std::uint32_t max_connections = kMaxServiceConnections;
  std::uint32_t backlog = kDefaultServiceBacklog;
  std::uint32_t max_frame_bytes = kMaxFrameBytes;
  std::uint32_t max_stored_plans = 4096;
  std::uint64_t expansion_ceiling = kMaxSearchExpansionsCeiling;
  // When true, an accepted snapshot is persisted so that a later incarnation can
  // reopen the store; the restored copy is marked as not fresh.
  bool persist_snapshots = true;
};

struct ServiceStats {
  std::uint64_t connections_accepted = 0;
  std::uint64_t frames_handled = 0;
  std::uint64_t frames_rejected = 0;
  std::uint64_t snapshots_ingested = 0;
  std::uint64_t plans_computed = 0;
  std::uint64_t plans_rejected = 0;
  std::uint64_t plans_cancelled = 0;
  std::uint64_t active_requests = 0;
  std::uint64_t fenced_frames = 0;
};

class Service {
 public:
  static Expected<std::unique_ptr<Service>> Start(const ServiceOptions& options);
  ~Service();

  Service(const Service&) = delete;
  Service& operator=(const Service&) = delete;

  [[nodiscard]] std::uint16_t port() const noexcept { return bound_port_; }
  [[nodiscard]] const IncarnationState& incarnation() const noexcept { return incarnation_; }
  [[nodiscard]] const std::string& state_dir() const noexcept { return options_.state_dir; }

  // Serves connections until Shutdown() is called or the listener fails.
  [[nodiscard]] Status Run();

  // Requests shutdown. Returns immediately; the accept loop stops after the
  // current poll completes and in-flight requests observe cancellation.
  void Shutdown();

  [[nodiscard]] ServiceStats Stats() const;

  // Handles one frame. Exposed so that the protocol can be exercised without a
  // socket, and so tests can drive fenced and malformed frames directly.
  [[nodiscard]] Frame HandleFrame(const Frame& frame);

 private:
  explicit Service(ServiceOptions options) : options_(std::move(options)) {}

  // Stops the listener and every live connection except the one named, so that
  // the connection that asked for shutdown can still deliver its reply.
  void StopConnections(void* except);
  [[nodiscard]] Frame HandleFrameFor(const Frame& frame, void* caller);

  // The planning thread runs one request at a time. It owns no socket: the
  // accepting thread owns every socket, so no socket operation ever crosses a
  // thread boundary.
  void ServeConnection(void* socket_handle);

  ServiceOptions options_;
  IncarnationState incarnation_{};
  std::uint16_t bound_port_ = 0;
  // Read by the accept loop and cleared by Shutdown() from another thread, so it
  // is accessed atomically rather than as a plain pointer.
  std::atomic<void*> listener_{nullptr};
  std::atomic<bool> stopping_{false};
  StateDirectoryLock directory_lock_;

  mutable std::mutex mutex_;
  std::shared_ptr<const TopologySnapshot> snapshot_;
  bool snapshot_fresh_ = false;
  std::shared_ptr<PlanStore> store_;
  // One worker per connection. Every worker owns its socket exclusively and
  // every socket wait is bounded, so a worker always returns and can be joined.
  std::vector<std::thread> workers_;
  std::vector<void*> active_connections_;
  std::map<std::uint64_t, CancelToken> cancellations_;
  ServiceStats stats_{};
};

// Client for the inspection service. One connection per client; a client is not
// thread safe.
class ServiceClient {
 public:
  struct Options {
    std::string host = kServiceBindAddress;
    std::uint16_t port = 0;
    std::uint32_t max_frame_bytes = kMaxFrameBytes;
  };

  static Expected<std::unique_ptr<ServiceClient>> Connect(const Options& options);
  ~ServiceClient();

  ServiceClient(const ServiceClient&) = delete;
  ServiceClient& operator=(const ServiceClient&) = delete;

  [[nodiscard]] Expected<HelloAckMessage> Hello(std::string_view client_name);

  // Pins every subsequent frame to the given epoch. Zero means "do not pin";
  // a non-zero pin that is older than the service epoch is fenced.
  void SetEpochPin(Epoch epoch) noexcept { epoch_pin_ = epoch; }
  [[nodiscard]] Epoch epoch_pin() const noexcept { return epoch_pin_; }

  [[nodiscard]] Expected<IngestAckMessage> Ingest(const TopologySnapshot& snapshot);
  [[nodiscard]] Expected<PlanningResult> Plan(const PlanningRequest& request,
                                              std::uint64_t cancel_token = 0);
  [[nodiscard]] Expected<ValidationReport> Validate(const PlanArtifact& plan,
                                                    const ValidationPolicy& policy);
  [[nodiscard]] Expected<PlanArtifact> GetPlan(const Digest256& digest);
  [[nodiscard]] Expected<StoreListAckMessage> StoreList();
  [[nodiscard]] Expected<CancelAckMessage> Cancel(std::uint64_t cancel_token);
  [[nodiscard]] Expected<StatsAckMessage> Stats();
  [[nodiscard]] Status Shutdown();

 private:
  explicit ServiceClient(Options options) : options_(std::move(options)) {}
  [[nodiscard]] Expected<Frame> Exchange(MessageKind kind, const std::string& payload);
  [[nodiscard]] Status SendFrame(const Frame& frame);

  Options options_;
  void* socket_handle_ = nullptr;
  std::uint64_t sequence_ = 0;
  Epoch epoch_pin_ = 0;
};

// Generates a fresh random incarnation identifier from the operating system's
// entropy source. Returns a zero identifier when no entropy source is available.
[[nodiscard]] IncarnationId GenerateIncarnationId();

// Milliseconds since the Unix epoch from the system clock.
[[nodiscard]] std::uint64_t UnixMillisNow();

}  // namespace opp
