// oppd: the Optical Path Planner inspection service.
//
// The service holds at most one sealed snapshot, an immutable plan store and an
// incarnation/epoch pair. It listens on loopback only. It is an inspection and
// planning surface: it never activates a path, reserves spectrum, mutates a
// transceiver or programs hardware.

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstdlib>
#include <iostream>
#include <string>

#include "opp/opp.hpp"

namespace {

opp::Service* g_service = nullptr;

void HandleSignal(int) {
  if (g_service != nullptr) g_service->Shutdown();
}

const char* kUsage =
    "oppd - Optical Path Planner inspection service\n"
    "\n"
    "usage: oppd --state <dir> [options]\n"
    "\n"
    "  --state <dir>        directory holding the incarnation record, the persisted\n"
    "                       snapshot and (by default) the plan store. Required.\n"
    "  --store <dir>        override the plan store directory.\n"
    "  --port <n>           listen port; 0 selects an ephemeral port. Default 0.\n"
    "  --bind <address>     dotted-quad IPv4 address. Default 127.0.0.1.\n"
    "  --max-plans <n>      plan store capacity. Default 4096.\n"
    "  --max-connections <n> concurrent connection bound. Default 64.\n"
    "  --no-persist         do not persist the ingested snapshot.\n"
    "\n"
    "On start the service prints one line to stdout:\n"
    "  LISTENING <port> <incarnation> <epoch> <epoch-continuity>\n";

std::string NextValue(int argc, char** argv, int* index, const char* name) {
  if (*index + 1 >= argc) {
    std::cerr << "oppd: " << name << " requires a value\n";
    std::exit(2);
  }
  *index += 1;
  return argv[*index];
}

}  // namespace

int main(int argc, char** argv) {
  opp::ServiceOptions options;
  for (int i = 1; i < argc; ++i) {
    const std::string token = argv[i];
    if (token == "--help" || token == "-h") {
      std::cout << kUsage;
      return 0;
    }
    if (token == "--no-persist") {
      options.persist_snapshots = false;
      continue;
    }
    if (token == "--state") {
      options.state_dir = NextValue(argc, argv, &i, "--state");
      continue;
    }
    if (token == "--store") {
      options.store_root = NextValue(argc, argv, &i, "--store");
      continue;
    }
    if (token == "--bind") {
      options.bind_address = NextValue(argc, argv, &i, "--bind");
      continue;
    }
    if (token == "--port") {
      const std::string value = NextValue(argc, argv, &i, "--port");
      const auto parsed = opp::ParseU16(value);
      if (!parsed.ok()) {
        std::cerr << "oppd: --port must be an unsigned integer\n";
        return 2;
      }
      options.port = parsed.value();
      continue;
    }
    if (token == "--max-plans") {
      const std::string value = NextValue(argc, argv, &i, "--max-plans");
      const auto parsed = opp::ParseU32(value);
      if (!parsed.ok()) {
        std::cerr << "oppd: --max-plans must be an unsigned integer\n";
        return 2;
      }
      options.max_stored_plans = parsed.value();
      continue;
    }
    if (token == "--max-connections") {
      const std::string value = NextValue(argc, argv, &i, "--max-connections");
      const auto parsed = opp::ParseU32(value);
      if (!parsed.ok()) {
        std::cerr << "oppd: --max-connections must be an unsigned integer\n";
        return 2;
      }
      options.max_connections = parsed.value();
      continue;
    }
    std::cerr << "oppd: unknown argument '" << token << "'\n\n" << kUsage;
    return 2;
  }

  if (options.state_dir.empty()) {
    std::cerr << "oppd: --state is required\n\n" << kUsage;
    return 2;
  }

  const auto started = opp::Service::Start(options);
  if (!started.ok()) {
    std::cerr << "oppd: " << opp::StatusCodeName(started.status().code) << ": " << started.status().detail << "\n";
    return 1;
  }
  opp::Service& service = *started.value();
  g_service = &service;

  std::cout << "LISTENING " << service.port() << " " << service.incarnation().incarnation.ToHex() << " "
            << service.incarnation().epoch << " " << (service.incarnation().epoch_continuity ? "true" : "false")
            << std::endl;

  std::signal(SIGINT, HandleSignal);
  std::signal(SIGTERM, HandleSignal);

  const opp::Status status = service.Run();
  g_service = nullptr;
  if (status.failed()) {
    std::cerr << "oppd: " << opp::StatusCodeName(status.code) << ": " << status.detail << "\n";
    return 1;
  }
  return 0;
}
