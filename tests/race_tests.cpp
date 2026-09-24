// Concurrency and multi-process suite.
//
// The service proofs here use a real second operating-system process: the oppd
// binary is started, killed at a chosen lifecycle boundary and restarted. Every
// rendezvous is a logical one (a flag set by the search itself, or a service
// statistic) rather than a sleep or a wall-clock timeout.

#include <algorithm>
#include <atomic>
#include <cstdint>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "opp/opp.hpp"
#include "process_support.hpp"
#include "test_framework.hpp"
#include "test_support.hpp"

namespace {

using namespace opp;
using opp_test::ChildProcess;
using opp_test::Random;

PortKey Key(const char* node, const char* port) {
  return PortKey{NodeId::Trusted(node), PortId::Trusted(port)};
}

PlanningRequest MakeRequest(std::uint32_t from, std::uint32_t to, const char* id) {
  PlanningRequest request;
  request.id = RequestId::Trusted(id);
  request.source = PortKey{NodeId::Trusted("n" + std::to_string(from)), PortId::Trusted("c0")};
  request.destination = PortKey{NodeId::Trusted("n" + std::to_string(to)), PortId::Trusted("c0")};
  return request;
}

struct DaemonHandle {
  ChildProcess child;
  std::uint16_t port = 0;
  std::string incarnation;
  Epoch epoch = 0;
  bool epoch_continuity = false;
  bool valid = false;
};

// Starts oppd and blocks until it reports the port it bound. No timeout is used:
// the daemon either prints the line or the pipe closes, and a missing line is a
// defect in the daemon rather than something to paper over.
DaemonHandle StartDaemon(const std::string& state_dir, const std::vector<std::string>& extra_arguments = {}) {
  DaemonHandle handle;
  std::vector<std::string> arguments;
  arguments.push_back("--state");
  arguments.push_back(state_dir);
  arguments.push_back("--port");
  arguments.push_back("0");
  arguments.push_back("--bind");
  arguments.push_back("127.0.0.1");
  for (const std::string& extra : extra_arguments) arguments.push_back(extra);

  const auto spawned = opp_test::SpawnChild(OPP_DAEMON_BINARY, arguments);
  if (!spawned.ok()) {
    OPP_CHECK_MSG(false, "cannot start oppd: " + spawned.status().detail);
    return handle;
  }
  handle.child = spawned.value();
  const auto line = opp_test::ReadChildLine(&handle.child);
  if (!line.ok()) {
    OPP_CHECK_MSG(false, "oppd did not report a listening line: " + line.status().detail);
    return handle;
  }
  const auto tokens = SplitTokens(line.value());
  if (!tokens.ok() || tokens.value().size() < 5 || tokens.value()[0] != "LISTENING") {
    OPP_CHECK_MSG(false, "unexpected oppd banner: " + line.value());
    return handle;
  }
  const auto port = ParseU16(tokens.value()[1]);
  const auto epoch = ParseU64(tokens.value()[3]);
  if (!port.ok() || !epoch.ok()) {
    OPP_CHECK_MSG(false, "oppd banner did not parse: " + line.value());
    return handle;
  }
  handle.port = port.value();
  handle.incarnation = tokens.value()[2];
  handle.epoch = epoch.value();
  handle.epoch_continuity = tokens.value()[4] == "true";
  handle.valid = true;
  return handle;
}

std::unique_ptr<ServiceClient> ConnectClient(std::uint16_t port) {
  ServiceClient::Options options;
  options.host = "127.0.0.1";
  options.port = port;
  auto client = ServiceClient::Connect(options);
  if (!client.ok()) return nullptr;
  return std::move(client.value());
}

// A larger synthetic fabric used by the cancellation proof. Everything is
// published, so the search has real work to do rather than stopping at a gap.
Expected<TopologySnapshot> BuildLargeSnapshot() {
  SyntheticOptions options;
  options.seed = 4242;
  options.node_count = 120;
  options.degree = 4;
  options.slot_count = 32;
  options.slot_blocking_one_in = 6;
  options.generation = 7;
  options.id = "large";
  return GenerateSyntheticTopology(options);
}

// Sends raw bytes to the service port and closes. This is how the suite delivers
// frames that no client API would ever produce.
bool SendRawBytes(std::uint16_t port, const std::string& bytes) {
#if defined(_WIN32)
  static const bool winsock_ready = []() {
    WSADATA data;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }();
  if (!winsock_ready) return false;
  const SOCKET handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == INVALID_SOCKET) return false;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    closesocket(handle);
    return false;
  }
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const int chunk = static_cast<int>(std::min<std::size_t>(bytes.size() - offset, 1u << 16));
    const int sent = send(handle, bytes.data() + offset, chunk, 0);
    if (sent <= 0) break;
    offset += static_cast<std::size_t>(sent);
  }
  shutdown(handle, SD_BOTH);
  closesocket(handle);
  return true;
#else
  const int handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle < 0) return false;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    close(handle);
    return false;
  }
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const ssize_t sent = send(handle, bytes.data() + offset, bytes.size() - offset, 0);
    if (sent <= 0) break;
    offset += static_cast<std::size_t>(sent);
  }
  shutdown(handle, SHUT_RDWR);
  close(handle);
  return true;
#endif
}

}  // namespace

OPP_TEST(race, concurrent_planning_is_byte_identical) {
  const auto built = opp_test::BuildCompleteSnapshot(70, 12, 16, 6);
  OPP_REQUIRE(built.ok());
  const PlanningRequest request = MakeRequest(0, 9, "race-concurrent");

  const Planner planner;
  const PlanningResult reference = planner.Plan(built.value(), request);
  OPP_REQUIRE(reference.outcome == PlanOutcome::Feasible);

  constexpr std::uint32_t kThreads = 8;
  std::vector<std::thread> threads;
  std::vector<std::string> outputs(kThreads);
  std::vector<PlanOutcome> outcomes(kThreads, PlanOutcome::Refused);
  for (std::uint32_t i = 0; i < kThreads; ++i) {
    threads.emplace_back([&built, &request, &planner, &outputs, &outcomes, i]() {
      const PlanningResult result = planner.Plan(built.value(), request);
      outputs[i] = result.CanonicalBytes();
      outcomes[i] = result.outcome;
    });
  }
  for (std::thread& thread : threads) thread.join();
  for (std::uint32_t i = 0; i < kThreads; ++i) {
    OPP_CHECK(outcomes[i] == reference.outcome);
    OPP_CHECK_EQ(outputs[i], reference.CanonicalBytes());
  }
}

OPP_TEST(race, snapshot_swap_during_planning_never_tears) {
  auto first = opp_test::BuildCompleteSnapshot(71, 10, 12, 5);
  auto second = opp_test::BuildCompleteSnapshot(72, 10, 12, 5);
  OPP_REQUIRE(first.ok());
  OPP_REQUIRE(second.ok());
  OPP_CHECK(!(first.value().digest() == second.value().digest()));

  std::mutex mutex;
  std::shared_ptr<const TopologySnapshot> current =
      std::make_shared<const TopologySnapshot>(first.value());
  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> swaps{0};

  std::thread swapper([&]() {
    for (int i = 0; i < 400; ++i) {
      std::lock_guard<std::mutex> guard(mutex);
      current = (i % 2 == 0) ? std::make_shared<const TopologySnapshot>(second.value())
                             : std::make_shared<const TopologySnapshot>(first.value());
      swaps.fetch_add(1, std::memory_order_relaxed);
    }
    stop.store(true, std::memory_order_release);
  });

  const Planner planner;
  std::vector<std::thread> planners;
  std::atomic<std::uint64_t> torn{0};
  std::atomic<std::uint64_t> planned{0};
  for (std::uint32_t i = 0; i < 4; ++i) {
    planners.emplace_back([&]() {
      while (!stop.load(std::memory_order_acquire)) {
        std::shared_ptr<const TopologySnapshot> snapshot;
        {
          std::lock_guard<std::mutex> guard(mutex);
          snapshot = current;
        }
        const PlanningResult result = planner.Plan(*snapshot, MakeRequest(0, 8, "race-swap"));
        // Every result must name exactly the snapshot it planned against.
        if (!(result.snapshot_digest == snapshot->digest())) torn.fetch_add(1, std::memory_order_relaxed);
        if (result.outcome == PlanOutcome::Feasible) {
          if (!(result.candidates.front().snapshot_digest == snapshot->digest())) {
            torn.fetch_add(1, std::memory_order_relaxed);
          }
        }
        planned.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }
  swapper.join();
  for (std::thread& thread : planners) thread.join();

  OPP_CHECK_EQ(torn.load(), std::uint64_t{0});
  OPP_CHECK_MSG(planned.load() > 0, "no planning iteration ran during the swap");
  OPP_CHECK_EQ(swaps.load(), std::uint64_t{400});
}

OPP_TEST(race, store_survives_concurrent_writers) {
  const std::string root = opp_test::FreshTempDir("race-store");
  const auto built = opp_test::BuildCompleteSnapshot(70, 12, 16, 6);
  OPP_REQUIRE(built.ok());
  const Planner planner;

  // Distinct artifacts come from distinct requests, which change the sealed
  // request digest and therefore the plan identity.
  std::vector<PlanArtifact> artifacts;
  for (std::uint32_t i = 0; i < 8; ++i) {
    PlanningRequest request = MakeRequest(0, 9, ("race-store-" + std::to_string(i)).c_str());
    request.max_candidates = 4;
    const PlanningResult result = planner.Plan(built.value(), request);
    OPP_REQUIRE(result.outcome == PlanOutcome::Feasible);
    for (const PlanArtifact& plan : result.candidates) artifacts.push_back(plan);
  }
  OPP_REQUIRE(artifacts.size() >= 8);

  StoreOptions options;
  options.root = root;
  options.max_plans = 4096;
  const auto store = PlanStore::Open(options);
  OPP_REQUIRE(store.ok());

  constexpr std::uint32_t kThreads = 6;
  std::atomic<std::uint64_t> failures{0};
  std::vector<std::thread> threads;
  for (std::uint32_t i = 0; i < kThreads; ++i) {
    threads.emplace_back([&store, &artifacts, &failures, i]() {
      for (std::size_t round = 0; round < 4; ++round) {
        for (std::size_t index = i % artifacts.size(); index < artifacts.size(); index += kThreads) {
          if (store.value()->Put(artifacts[index]).failed()) failures.fetch_add(1, std::memory_order_relaxed);
          const auto fetched = store.value()->Get(artifacts[index].digest);
          if (!fetched.ok()) {
            failures.fetch_add(1, std::memory_order_relaxed);
            continue;
          }
          if (!(fetched.value().CanonicalBytes() == artifacts[index].CanonicalBytes())) {
            failures.fetch_add(1, std::memory_order_relaxed);
          }
        }
      }
    });
  }
  for (std::thread& thread : threads) thread.join();
  OPP_CHECK_EQ(failures.load(), std::uint64_t{0});

  std::vector<StoreEntry> entries;
  std::vector<std::string> rejected;
  OPP_CHECK(store.value()->List(&entries, &rejected).ok());
  OPP_CHECK(rejected.empty());
  OPP_CHECK_EQ(entries.size(), artifacts.size());

  // A concurrent reader that only ever observes complete files.
  std::atomic<std::uint64_t> partial{0};
  std::thread reader([&store, &entries, &partial]() {
    for (int round = 0; round < 200; ++round) {
      for (const StoreEntry& entry : entries) {
        const auto fetched = store.value()->Get(entry.digest);
        if (fetched.ok() && !fetched.value().VerifySeal().ok()) {
          partial.fetch_add(1, std::memory_order_relaxed);
        }
      }
    }
  });
  reader.join();
  OPP_CHECK_EQ(partial.load(), std::uint64_t{0});
  opp_test::RemoveTree(root);
}

OPP_TEST(race, cancellation_from_another_thread_is_a_rendezvous) {
  const auto built = opp_test::BuildCompleteSnapshot(74, 16, 24, 5);
  OPP_REQUIRE(built.ok());
  const PlanningRequest request = MakeRequest(0, 15, "race-cancel");
  const Planner planner;

  CancelToken token;
  std::atomic<std::uint64_t> reached{0};
  std::atomic<bool> released{false};
  std::atomic<bool> requested{false};
  constexpr std::uint64_t kRendezvous = 20;
  const SearchObserver observer = [&](const PlanningStatistics& statistics) {
    if (statistics.labels_expanded >= kRendezvous) {
      reached.store(statistics.labels_expanded, std::memory_order_release);
      // Hold the search at a known boundary until the other thread has asked for
      // cancellation. This is a rendezvous, not a delay.
      while (!released.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      requested.store(true, std::memory_order_release);
    }
  };

  PlanningResult result;
  std::thread worker([&]() { result = planner.Plan(built.value(), request, token, observer); });

  while (reached.load(std::memory_order_acquire) < kRendezvous) {
    std::this_thread::yield();
  }
  token.Request();
  released.store(true, std::memory_order_release);
  worker.join();

  OPP_CHECK(requested.load());
  OPP_CHECK(result.outcome == PlanOutcome::Cancelled);
  OPP_CHECK(result.candidates.empty());
  OPP_CHECK(result.status.code == StatusCode::Cancelled);
}

OPP_TEST(race, concurrent_ingest_and_plan_is_consistent) {
  const std::string state_dir = opp_test::FreshTempDir("race-ingest");
  const auto large = BuildLargeSnapshot();
  OPP_REQUIRE(large.ok());

  DaemonHandle daemon = StartDaemon(state_dir, {"--no-persist"});
  OPP_REQUIRE(daemon.valid);
  OPP_CHECK(daemon.epoch >= 1);

  auto ingest_client = ConnectClient(daemon.port);
  auto plan_client = ConnectClient(daemon.port);
  OPP_REQUIRE(ingest_client != nullptr);
  OPP_REQUIRE(plan_client != nullptr);

  const auto hello = plan_client->Hello("race");
  OPP_REQUIRE(hello.ok());
  OPP_CHECK_EQ(hello.value().epoch, daemon.epoch);

  const auto ingested = ingest_client->Ingest(large.value());
  OPP_REQUIRE(ingested.ok());
  OPP_CHECK(ingested.value().snapshot_digest == large.value().digest());

  const PlanningRequest request = MakeRequest(0, 60, "race-ingest-plan");
  const auto planned = plan_client->Plan(request);
  OPP_REQUIRE(planned.ok());
  OPP_CHECK(planned.value().outcome == PlanOutcome::Feasible);
  if (planned.value().outcome == PlanOutcome::Feasible) {
    OPP_CHECK(planned.value().candidates.front().snapshot_digest == large.value().digest());
  }

  const auto stored = plan_client->StoreList();
  OPP_REQUIRE(stored.ok());
  OPP_CHECK_EQ(stored.value().digests.size(), std::size_t{1});
  OPP_CHECK(stored.value().rejected_files.empty());

  const Status plan_shutdown = plan_client->Shutdown();
  OPP_CHECK_MSG(plan_shutdown.ok(), "shutdown failed: " + plan_shutdown.detail);
  const auto exit_code = opp_test::WaitChild(&daemon.child);
  OPP_REQUIRE(exit_code.ok());
  OPP_CHECK_MSG(exit_code.value() == 0, "daemon exit code " + std::to_string(exit_code.value()));
  opp_test::CloseChild(&daemon.child);
  opp_test::RemoveTree(state_dir);
}

OPP_TEST(race, kill_and_restart_fences_the_previous_epoch) {
  const std::string state_dir = opp_test::FreshTempDir("race-restart");
  const auto built = opp_test::BuildCompleteSnapshot(75, 10, 12, 0);
  OPP_REQUIRE(built.ok());

  DaemonHandle first = StartDaemon(state_dir);
  OPP_REQUIRE(first.valid);
  OPP_CHECK(first.epoch_continuity);
  const Epoch first_epoch = first.epoch;
  const std::string first_incarnation = first.incarnation;
  const std::uint64_t first_pid = first.child.process_id;

  auto client = ConnectClient(first.port);
  OPP_REQUIRE(client != nullptr);
  const auto hello = client->Hello("first");
  OPP_REQUIRE(hello.ok());
  OPP_CHECK_EQ(hello.value().epoch, first_epoch);
  const auto ingested = client->Ingest(built.value());
  OPP_REQUIRE(ingested.ok());
  const PlanningRequest request = MakeRequest(0, 5, "restart");
  const auto planned = client->Plan(request);
  OPP_REQUIRE(planned.ok());
  OPP_REQUIRE(planned.value().outcome == PlanOutcome::Feasible);
  const PlanArtifact plan = planned.value().candidates.front();

  // A second instance must refuse to share the state directory while the first
  // one is alive.
  std::vector<std::string> arguments{"--state", state_dir, "--port", "0"};
  const auto blocked = opp_test::SpawnChild(OPP_DAEMON_BINARY, arguments);
  OPP_REQUIRE(blocked.ok());
  ChildProcess blocked_child = blocked.value();
  const auto blocked_exit = opp_test::WaitChild(&blocked_child);
  OPP_REQUIRE(blocked_exit.ok());
  OPP_CHECK_MSG(blocked_exit.value() != 0, "a second instance shared the live state directory");
  opp_test::CloseChild(&blocked_child);

  // Kill the first incarnation without letting it shut down cleanly.
  OPP_REQUIRE(opp_test::KillChild(&first.child).ok());
  const auto killed_exit = opp_test::WaitChild(&first.child);
  OPP_REQUIRE(killed_exit.ok());
  OPP_CHECK_MSG(killed_exit.value() != 0, "a forcefully terminated daemon reported success");
  opp_test::CloseChild(&first.child);
  client.reset();

  DaemonHandle second = StartDaemon(state_dir);
  OPP_REQUIRE(second.valid);
  OPP_CHECK_MSG(second.epoch > first_epoch, "the restarted service did not advance its epoch");
  OPP_CHECK_MSG(second.incarnation != first_incarnation, "the restarted service reused its incarnation");
  OPP_CHECK(second.child.process_id != first_pid);

  // A frame pinned to the previous epoch is fenced.
  auto fenced_client = ConnectClient(second.port);
  OPP_REQUIRE(fenced_client != nullptr);
  fenced_client->SetEpochPin(first_epoch);
  const auto fenced = fenced_client->Stats();
  OPP_CHECK_MSG(!fenced.ok(), "a frame pinned to a superseded epoch was accepted");
  OPP_CHECK(fenced.status().code == StatusCode::Fenced);

  // A frame pinned to the current epoch is served.
  auto current_client = ConnectClient(second.port);
  OPP_REQUIRE(current_client != nullptr);
  current_client->SetEpochPin(second.epoch);
  const auto stats = current_client->Stats();
  OPP_REQUIRE(stats.ok());
  OPP_CHECK_EQ(stats.value().epoch, second.epoch);
  OPP_CHECK_MSG(stats.value().fenced_frames >= 1, "the service did not account for the fenced frame");

  // Evidence restored from disk is never fresh: it must not yield FEASIBLE.
  const auto hello_after = current_client->Hello("second");
  OPP_REQUIRE(hello_after.ok());
  OPP_CHECK(hello_after.value().has_snapshot);
  OPP_CHECK_MSG(!hello_after.value().snapshot_fresh, "restored evidence was reported as fresh");
  const auto restored_plan = current_client->Plan(request);
  OPP_CHECK_MSG(!restored_plan.ok() || restored_plan.value().outcome == PlanOutcome::Indeterminate,
                "restored evidence produced a decision");
  if (restored_plan.ok()) {
    OPP_CHECK((restored_plan.value().limitations & kLimitationRestoredEvidence) != 0);
    OPP_CHECK(restored_plan.value().candidates.empty());
  }

  // The artifact persisted by the previous incarnation is still readable, and it
  // is not valid against the restored generation because the service will not
  // call restored evidence fresh.
  const auto fetched = current_client->GetPlan(plan.digest);
  OPP_REQUIRE(fetched.ok());
  OPP_CHECK_EQ(fetched.value().CanonicalBytes(), plan.CanonicalBytes());
  const auto validation = current_client->Validate(plan, ValidationPolicy{});
  OPP_REQUIRE(validation.ok());
  OPP_CHECK(validation.value().validity == PlanValidity::NotFresh);

  // Re-ingesting makes the same request decidable again.
  const auto reingested = current_client->Ingest(built.value());
  OPP_REQUIRE(reingested.ok());
  const auto replanned = current_client->Plan(request);
  OPP_REQUIRE(replanned.ok());
  OPP_CHECK(replanned.value().outcome == PlanOutcome::Feasible);
  OPP_CHECK(validation.value().validity != PlanValidity::Valid);

  const Status current_shutdown = current_client->Shutdown();
  OPP_CHECK_MSG(current_shutdown.ok(), "shutdown failed: " + current_shutdown.detail);
  const auto clean_exit = opp_test::WaitChild(&second.child);
  OPP_REQUIRE(clean_exit.ok());
  OPP_CHECK_MSG(clean_exit.value() == 0, "daemon exit code " + std::to_string(clean_exit.value()));
  opp_test::CloseChild(&second.child);
  opp_test::RemoveTree(state_dir);
}

OPP_TEST(race, remote_cancellation_publishes_nothing) {
  const std::string state_dir = opp_test::FreshTempDir("race-remote-cancel");
  const auto large = BuildLargeSnapshot();
  OPP_REQUIRE(large.ok());

  DaemonHandle daemon = StartDaemon(state_dir);
  OPP_REQUIRE(daemon.valid);

  auto ingest_client = ConnectClient(daemon.port);
  auto worker_client = ConnectClient(daemon.port);
  auto cancel_client = ConnectClient(daemon.port);
  OPP_REQUIRE(ingest_client != nullptr && worker_client != nullptr && cancel_client != nullptr);
  OPP_REQUIRE(ingest_client->Ingest(large.value()).ok());

  const auto before = cancel_client->StoreList();
  OPP_REQUIRE(before.ok());
  const std::size_t stored_before = before.value().digests.size();

  PlanningRequest request = MakeRequest(0, 100, "remote-cancel");
  request.max_search_expansions = kMaxSearchExpansionsCeiling;
  request.max_search_labels = kMaxSearchLabelsCeiling;
  constexpr std::uint64_t kCancelToken = 0xC0FFEEull;

  Expected<PlanningResult> outcome = Failure(StatusCode::Internal, "not run");
  std::thread worker([&]() { outcome = worker_client->Plan(request, kCancelToken); });

  // Rendezvous with the in-flight request: the service reports one active
  // request while the search is running.
  bool cancel_delivered = false;
  while (true) {
    const auto stats = cancel_client->Stats();
    if (!stats.ok()) break;
    if (stats.value().active_requests >= 1) {
      const auto cancelled = cancel_client->Cancel(kCancelToken);
      OPP_REQUIRE(cancelled.ok());
      cancel_delivered = cancelled.value().found;
      break;
    }
    if (stats.value().plans_computed + stats.value().plans_rejected > 0) {
      // The search completed before the cancellation could be delivered; the
      // completed outcome is checked below.
      break;
    }
  }
  worker.join();

  const auto after = cancel_client->StoreList();
  OPP_REQUIRE(after.ok());

  if (cancel_delivered) {
    OPP_REQUIRE(outcome.ok());
    OPP_CHECK_MSG(outcome.value().outcome == PlanOutcome::Cancelled,
                  std::string("cancelled request reported ") + PlanOutcomeName(outcome.value().outcome));
    OPP_CHECK(outcome.value().candidates.empty());
    OPP_CHECK_EQ(after.value().digests.size(), stored_before);
  } else {
    OPP_REQUIRE(outcome.ok());
    OPP_CHECK(outcome.value().outcome == PlanOutcome::Feasible ||
              outcome.value().outcome == PlanOutcome::Indeterminate);
  }

  // The service is still healthy after the cancellation.
  const auto stats = cancel_client->Stats();
  OPP_REQUIRE(stats.ok());
  OPP_CHECK_EQ(stats.value().active_requests, std::uint64_t{0});
  OPP_CHECK(stats.value().plans_cancelled >= (cancel_delivered ? 1u : 0u));

  const Status cancel_shutdown = cancel_client->Shutdown();
  OPP_CHECK_MSG(cancel_shutdown.ok(), "shutdown failed: " + cancel_shutdown.detail);
  const auto exit_code = opp_test::WaitChild(&daemon.child);
  OPP_REQUIRE(exit_code.ok());
  OPP_CHECK_MSG(exit_code.value() == 0, "daemon exit code " + std::to_string(exit_code.value()));
  opp_test::CloseChild(&daemon.child);
  opp_test::RemoveTree(state_dir);
}

OPP_TEST(race, malformed_frames_do_not_take_the_service_down) {
  const std::string state_dir = opp_test::FreshTempDir("race-malformed");
  DaemonHandle daemon = StartDaemon(state_dir, {"--no-persist"});
  OPP_REQUIRE(daemon.valid);

  auto client = ConnectClient(daemon.port);
  OPP_REQUIRE(client != nullptr);
  OPP_REQUIRE(client->Hello("malformed").ok());

  // A declaration of more payload than the bound permits must be refused before
  // anything is allocated, and the listener must survive it.
  {
    ByteWriter writer;
    writer.U32(kFrameMagic);
    writer.U32(kProtocolVersion);
    writer.U32(static_cast<std::uint32_t>(MessageKind::Ingest));
    writer.U64(1);
    writer.U64(0);
    writer.U32(kMaxFrameBytes + 1);
    std::string oversized = writer.buffer();
    oversized.append(1024, '\0');
    OPP_CHECK(SendRawBytes(daemon.port, oversized));
  }

  // Garbage that is not a frame at all.
  OPP_CHECK(SendRawBytes(daemon.port, std::string("not a frame at all, not even close")));

  // A frame with an unrecognised transport revision.
  {
    ByteWriter writer;
    writer.U32(kFrameMagic);
    writer.U32(kProtocolVersion + 1);
    writer.U32(static_cast<std::uint32_t>(MessageKind::Stats));
    writer.U64(2);
    writer.U64(0);
    writer.U32(0);
    std::string frame = writer.buffer();
    frame.append(32, '\0');
    OPP_CHECK(SendRawBytes(daemon.port, frame));
  }

  // A well formed header with a body that fails its checksum.
  {
    Frame valid;
    valid.kind = MessageKind::Stats;
    valid.sequence = 3;
    std::string frame = EncodeFrame(valid);
    frame[frame.size() - 1] = static_cast<char>(frame[frame.size() - 1] ^ 0xff);
    OPP_CHECK(SendRawBytes(daemon.port, frame));
  }

  const auto still_alive = client->Stats();
  OPP_REQUIRE(still_alive.ok());
  OPP_CHECK_EQ(still_alive.value().plans_computed, std::uint64_t{0});

  const auto stats_after = client->Stats();
  OPP_REQUIRE(stats_after.ok());
  OPP_CHECK(stats_after.value().frames_handled >= 2);
  OPP_CHECK_MSG(stats_after.value().frames_rejected >= 3,
                "malformed frames were not accounted as rejected");

  const Status client_shutdown = client->Shutdown();
  OPP_CHECK_MSG(client_shutdown.ok(), "shutdown failed: " + client_shutdown.detail);
  const auto exit_code = opp_test::WaitChild(&daemon.child);
  OPP_REQUIRE(exit_code.ok());
  OPP_CHECK_MSG(exit_code.value() == 0, "daemon exit code " + std::to_string(exit_code.value()));
  opp_test::CloseChild(&daemon.child);
  opp_test::RemoveTree(state_dir);
}

OPP_TEST(race, planner_is_reentrant_across_snapshots) {
  const auto first = opp_test::BuildCompleteSnapshot(76, 10, 12, 4);
  const auto second = opp_test::BuildCompleteSnapshot(77, 12, 12, 4);
  OPP_REQUIRE(first.ok());
  OPP_REQUIRE(second.ok());

  const Planner planner;
  PlanningResult result_a;
  PlanningResult result_b;
  std::thread thread_a([&]() { result_a = planner.Plan(first.value(), MakeRequest(0, 8, "reentrant-a")); });
  std::thread thread_b([&]() { result_b = planner.Plan(second.value(), MakeRequest(0, 10, "reentrant-b")); });
  thread_a.join();
  thread_b.join();

  OPP_CHECK(result_a.outcome == PlanOutcome::Feasible);
  OPP_CHECK(result_b.outcome == PlanOutcome::Feasible);
  OPP_CHECK(result_a.snapshot_digest == first.value().digest());
  OPP_CHECK(result_b.snapshot_digest == second.value().digest());
  if (!result_a.candidates.empty()) {
    OPP_CHECK(result_a.candidates.front().snapshot_digest == first.value().digest());
  }
  if (!result_b.candidates.empty()) {
    OPP_CHECK(result_b.candidates.front().snapshot_digest == second.value().digest());
  }
}
