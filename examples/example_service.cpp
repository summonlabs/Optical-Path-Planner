// The inspection service over real loopback TCP: ingest, plan, validate, stop.
//
// The service is started in this process for brevity; oppd runs exactly the same
// code as a separate process, which is what the multi-process tests exercise.

#include <filesystem>
#include <iostream>
#include <string>

#include "opp/opp.hpp"

int main() {
  using namespace opp;

  ServiceOptions options;
  // The service state lives in the system temporary directory so that running
  // the example never writes into the directory it happens to be started from.
  options.state_dir = (std::filesystem::temp_directory_path() / "opp-example-service-state").string();
  options.port = 0;
  options.persist_snapshots = false;
  options.max_stored_plans = 32;

  const auto started = Service::Start(options);
  if (!started.ok()) {
    std::cerr << "start: " << started.status().detail << "\n";
    return 1;
  }
  Service& service = *started.value();
  std::cout << "service incarnation " << service.incarnation().incarnation.ToHex() << " epoch "
            << service.incarnation().epoch << " port " << service.port() << "\n";

  // Run the accept loop on a background thread so this thread can be the client.
  std::thread server([&service]() {
    const Status status = service.Run();
    if (status.failed()) std::cerr << "run: " << status.detail << "\n";
  });

  ServiceClient::Options client_options;
  client_options.host = "127.0.0.1";
  client_options.port = service.port();
  const auto client = ServiceClient::Connect(client_options);
  if (!client.ok()) {
    std::cerr << "connect: " << client.status().detail << "\n";
    service.Shutdown();
    server.join();
    return 1;
  }

  const auto hello = client.value()->Hello("example");
  if (!hello.ok()) {
    std::cerr << "hello: " << hello.status().detail << "\n";
    service.Shutdown();
    server.join();
    return 1;
  }
  std::cout << "service library " << hello.value().library_version << " epoch " << hello.value().epoch
            << " has_snapshot=" << (hello.value().has_snapshot ? "true" : "false") << "\n";

  const auto snapshot = BuildExampleTopology();
  if (!snapshot.ok()) {
    std::cerr << snapshot.status().detail << "\n";
    service.Shutdown();
    server.join();
    return 1;
  }
  const auto ingested = client.value()->Ingest(snapshot.value());
  if (!ingested.ok()) {
    std::cerr << "ingest: " << ingested.status().detail << "\n";
    service.Shutdown();
    server.join();
    return 1;
  }
  std::cout << "ingested snapshot " << ingested.value().snapshot_id.str() << " generation "
            << ingested.value().generation << "\n";

  PlanningRequest request;
  request.id = RequestId::Trusted("example-service");
  request.source = PortKey{NodeId::Trusted("a"), PortId::Trusted("in")};
  request.destination = PortKey{NodeId::Trusted("c"), PortId::Trusted("out")};
  const auto planned = client.value()->Plan(request);
  if (!planned.ok()) {
    std::cerr << "plan: " << planned.status().detail << "\n";
    service.Shutdown();
    server.join();
    return 1;
  }
  std::cout << "remote outcome " << PlanOutcomeName(planned.value().outcome) << " candidates "
            << planned.value().candidates.size() << "\n";
  if (planned.value().outcome != PlanOutcome::Feasible) {
    service.Shutdown();
    server.join();
    return 1;
  }

  const PlanArtifact& plan = planned.value().candidates.front();
  const auto stored = client.value()->GetPlan(plan.digest);
  if (!stored.ok()) {
    std::cerr << "get plan: " << stored.status().detail << "\n";
    service.Shutdown();
    server.join();
    return 1;
  }
  std::cout << "stored artifact digest " << stored.value().DigestHex() << "\n";

  const auto validation = client.value()->Validate(plan, ValidationPolicy{});
  if (!validation.ok()) {
    std::cerr << "validate: " << validation.status().detail << "\n";
    service.Shutdown();
    server.join();
    return 1;
  }
  std::cout << "validation " << PlanValidityName(validation.value().validity) << "\n";

  const auto stats = client.value()->Stats();
  if (stats.ok()) {
    std::cout << "service stats: plans=" << stats.value().plans_computed
              << " ingest=" << stats.value().snapshots_ingested
              << " fenced=" << stats.value().fenced_frames << "\n";
  }

  const Status stopped = client.value()->Shutdown();
  if (stopped.failed()) std::cerr << "shutdown: " << stopped.detail << "\n";
  server.join();
  return 0;
}
