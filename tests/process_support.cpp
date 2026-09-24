#include "process_support.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace opp_test {

namespace {

// Every live child is tracked so that a case which returns early can never
// leave a daemon behind holding a temp directory or a listener.
std::mutex& ChildRegistryMutex() {
  static std::mutex mutex;
  return mutex;
}

// Copies of the live handles, so the registry stays valid even though the
// ChildProcess value itself is returned and copied by value.
struct TrackedChild {
  void* process_handle = nullptr;
  std::uint64_t process_id = 0;
};

std::vector<TrackedChild>& ChildRegistry() {
  static std::vector<TrackedChild> registry;
  return registry;
}

void RegisterChild(const ChildProcess& child) {
  std::lock_guard<std::mutex> guard(ChildRegistryMutex());
  TrackedChild tracked;
  tracked.process_handle = child.process_handle;
  tracked.process_id = child.process_id;
  ChildRegistry().push_back(tracked);
}

void UnregisterChild(const ChildProcess& child) {
  std::lock_guard<std::mutex> guard(ChildRegistryMutex());
  std::vector<TrackedChild>& registry = ChildRegistry();
  registry.erase(std::remove_if(registry.begin(), registry.end(),
                                [&child](const TrackedChild& tracked) {
                                  return tracked.process_id == child.process_id;
                                }),
                 registry.end());
}

struct ChildReaper {
  ~ChildReaper() {
    std::lock_guard<std::mutex> guard(ChildRegistryMutex());
    for (const TrackedChild& tracked : ChildRegistry()) {
      ChildProcess child;
      child.process_handle = tracked.process_handle;
      child.process_id = tracked.process_id;
      KillChild(&child);
    }
    ChildRegistry().clear();
  }
};

ChildReaper& Reaper() {
  static ChildReaper reaper;
  return reaper;
}

}  // namespace

using opp::Expected;
using opp::Failure;
using opp::OkStatus;
using opp::Status;
using opp::StatusCode;

#if defined(_WIN32)

namespace {

std::string QuoteArgument(const std::string& argument) {
  std::string quoted = "\"";
  for (char c : argument) {
    if (c == '"') quoted += "\\\"";
    quoted.push_back(c);
  }
  quoted += "\"";
  return quoted;
}

}  // namespace

Expected<ChildProcess> SpawnChild(const std::string& program, const std::vector<std::string>& arguments) {
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;

  HANDLE read_end = nullptr;
  HANDLE write_end = nullptr;
  if (CreatePipe(&read_end, &write_end, &attributes, 0) == 0) {
    return Failure(StatusCode::IoFailure, "cannot create a stdout pipe for the child process");
  }
  SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);

  HANDLE null_output = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes,
                                   OPEN_EXISTING, 0, nullptr);

  std::string command_line = QuoteArgument(program);
  for (const std::string& argument : arguments) {
    command_line.push_back(' ');
    command_line += QuoteArgument(argument);
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = write_end;
  startup.hStdError = null_output == INVALID_HANDLE_VALUE ? write_end : null_output;
  startup.hStdInput = nullptr;

  PROCESS_INFORMATION information{};
  std::wstring wide(command_line.begin(), command_line.end());
  const BOOL created = CreateProcessW(nullptr, wide.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                                      nullptr, &startup, &information);
  CloseHandle(write_end);
  if (null_output != INVALID_HANDLE_VALUE) CloseHandle(null_output);
  if (created == 0) {
    CloseHandle(read_end);
    return Failure(StatusCode::IoFailure, "cannot start '" + program + "'");
  }

  (void)Reaper();
  ChildProcess child;
  child.process_handle = information.hProcess;
  child.thread_handle = information.hThread;
  child.stdout_read = read_end;
  child.process_id = information.dwProcessId;
  RegisterChild(child);
  return child;
}

Expected<std::string> ReadChildLine(ChildProcess* child) {
  if (child == nullptr || child->stdout_read == nullptr) {
    return Failure(StatusCode::InvalidArgument, "the child has no stdout pipe");
  }
  std::string line;
  char buffer[1];
  DWORD read = 0;
  while (true) {
    if (ReadFile(child->stdout_read, buffer, 1, &read, nullptr) == 0 || read == 0) {
      if (line.empty()) return Failure(StatusCode::NotFound, "the child closed its standard output");
      return line;
    }
    if (buffer[0] == '\n') return line;
    if (buffer[0] != '\r') line.push_back(buffer[0]);
    if (line.size() > 4096) return Failure(StatusCode::LimitExceeded, "the child produced an overlong line");
  }
}

Status KillChild(ChildProcess* child) {
  if (child == nullptr || child->process_handle == nullptr) {
    return Failure(StatusCode::InvalidArgument, "there is no child process to terminate");
  }
  if (TerminateProcess(child->process_handle, 0xDEAD) == 0) {
    return Failure(StatusCode::IoFailure, "cannot terminate the child process");
  }
  WaitForSingleObject(child->process_handle, INFINITE);
  return OkStatus();
}

Expected<int> WaitChild(ChildProcess* child) {
  if (child == nullptr || child->process_handle == nullptr) {
    return Failure(StatusCode::InvalidArgument, "there is no child process to wait for");
  }
  WaitForSingleObject(child->process_handle, INFINITE);
  DWORD exit_code = 0;
  if (GetExitCodeProcess(child->process_handle, &exit_code) == 0) {
    return Failure(StatusCode::IoFailure, "cannot read the child exit code");
  }
  child->reaped = true;
  return static_cast<int>(exit_code);
}

void CloseChild(ChildProcess* child) {
  if (child == nullptr) return;
  UnregisterChild(*child);
  if (child->stdout_read != nullptr) CloseHandle(child->stdout_read);
  if (child->thread_handle != nullptr) CloseHandle(child->thread_handle);
  if (child->process_handle != nullptr) CloseHandle(child->process_handle);
  child->stdout_read = nullptr;
  child->thread_handle = nullptr;
  child->process_handle = nullptr;
}

bool ProcessAlive(std::uint64_t process_id) {
  HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(process_id));
  if (handle == nullptr) return false;
  DWORD exit_code = 0;
  const bool alive = GetExitCodeProcess(handle, &exit_code) != 0 && exit_code == STILL_ACTIVE;
  CloseHandle(handle);
  return alive;
}

#else

Expected<ChildProcess> SpawnChild(const std::string& program, const std::vector<std::string>& arguments) {
  int descriptors[2];
  if (pipe(descriptors) != 0) {
    return Failure(StatusCode::IoFailure, "cannot create a stdout pipe for the child process");
  }
  const pid_t pid = fork();
  if (pid < 0) {
    close(descriptors[0]);
    close(descriptors[1]);
    return Failure(StatusCode::IoFailure, "cannot fork");
  }
  if (pid == 0) {
    dup2(descriptors[1], STDOUT_FILENO);
    const int null_fd = open("/dev/null", O_WRONLY);
    if (null_fd >= 0) dup2(null_fd, STDERR_FILENO);
    close(descriptors[0]);
    close(descriptors[1]);
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(program.c_str()));
    for (const std::string& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
    argv.push_back(nullptr);
    execv(program.c_str(), argv.data());
    _exit(127);
  }
  close(descriptors[1]);
  (void)Reaper();
  ChildProcess child;
  child.process_id = static_cast<std::uint64_t>(pid);
  child.stdout_read = reinterpret_cast<void*>(static_cast<intptr_t>(descriptors[0]));
  RegisterChild(child);
  return child;
}

Expected<std::string> ReadChildLine(ChildProcess* child) {
  if (child == nullptr || child->stdout_read == nullptr) {
    return Failure(StatusCode::InvalidArgument, "the child has no stdout pipe");
  }
  const int descriptor = static_cast<int>(reinterpret_cast<intptr_t>(child->stdout_read));
  std::string line;
  char buffer[1];
  while (true) {
    const ssize_t read_bytes = read(descriptor, buffer, 1);
    if (read_bytes <= 0) {
      if (line.empty()) return Failure(StatusCode::NotFound, "the child closed its standard output");
      return line;
    }
    if (buffer[0] == '\n') return line;
    if (buffer[0] != '\r') line.push_back(buffer[0]);
    if (line.size() > 4096) return Failure(StatusCode::LimitExceeded, "the child produced an overlong line");
  }
}

Status KillChild(ChildProcess* child) {
  if (child == nullptr) return Failure(StatusCode::InvalidArgument, "there is no child process");
  if (kill(static_cast<pid_t>(child->process_id), SIGKILL) != 0) {
    return Failure(StatusCode::IoFailure, "cannot terminate the child process");
  }
  int status = 0;
  waitpid(static_cast<pid_t>(child->process_id), &status, 0);
  return OkStatus();
}

Expected<int> WaitChild(ChildProcess* child) {
  if (child == nullptr) return Failure(StatusCode::InvalidArgument, "there is no child process");
  int status = 0;
  if (waitpid(static_cast<pid_t>(child->process_id), &status, 0) < 0) {
    return Failure(StatusCode::IoFailure, "cannot wait for the child process");
  }
  child->reaped = true;
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  return 128 + WTERMSIG(status);
}

void CloseChild(ChildProcess* child) {
  if (child == nullptr) return;
  UnregisterChild(*child);
  if (child->stdout_read != nullptr) {
    close(static_cast<int>(reinterpret_cast<intptr_t>(child->stdout_read)));
  }
  child->stdout_read = nullptr;
}

bool ProcessAlive(std::uint64_t process_id) {
  return kill(static_cast<pid_t>(process_id), 0) == 0;
}

#endif

}  // namespace opp_test
