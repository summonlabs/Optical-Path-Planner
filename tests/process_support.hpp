#pragma once

// Real operating-system process control for the service tests.
//
// These helpers start an actual executable, read its stdout through a pipe and
// terminate it at a chosen lifecycle boundary. Threads are never used as a
// substitute for a second process.

#include <cstdint>
#include <string>
#include <vector>

#include "opp/status.hpp"

namespace opp_test {

struct ChildProcess {
  void* process_handle = nullptr;
  void* thread_handle = nullptr;
  void* stdout_read = nullptr;
  std::uint64_t process_id = 0;
  bool reaped = false;
};

// Starts a program with the given arguments, redirecting stdout into a pipe that
// the parent reads. stderr is discarded.
opp::Expected<ChildProcess> SpawnChild(const std::string& program, const std::vector<std::string>& arguments);

// Reads one newline terminated line from the child's stdout. Blocks until a line
// is available or the pipe closes; returns NotFound when the child closed it.
opp::Expected<std::string> ReadChildLine(ChildProcess* child);

// Forcefully terminates the child. This models a crash, not a clean shutdown.
opp::Status KillChild(ChildProcess* child);

// Waits for the child to exit and returns its exit code.
opp::Expected<int> WaitChild(ChildProcess* child);

// Closes handles and releases resources. Safe to call more than once.
void CloseChild(ChildProcess* child);

// True when a process with the given identifier is currently running.
bool ProcessAlive(std::uint64_t process_id);

}  // namespace opp_test
