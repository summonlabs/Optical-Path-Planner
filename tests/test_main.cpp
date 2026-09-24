#include "test_framework.hpp"

#include <cstdio>
#include <cstring>
#include <exception>
#include <string>

namespace opp_test {

std::uint64_t g_checks = 0;
std::uint64_t g_failures = 0;
std::string g_current;

std::vector<Case>& Registry() {
  static std::vector<Case> registry;
  return registry;
}

Registrar::Registrar(const char* suite, const char* name, std::function<void()> body) {
  Case entry;
  entry.suite = suite;
  entry.name = name;
  entry.body = std::move(body);
  Registry().push_back(std::move(entry));
}

void Fail(const char* file, int line, const std::string& message) {
  g_failures += 1;
  std::fprintf(stderr, "FAIL %s: %s\n  at %s:%d\n", g_current.c_str(), message.c_str(), file, line);
  std::fflush(stderr);
  throw Failure{message};
}

int RunAll(int argc, char** argv) {
  std::string filter;
  bool list_only = false;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--filter") == 0 && i + 1 < argc) {
      filter = argv[++i];
      continue;
    }
    if (std::strcmp(argv[i], "--list") == 0) {
      list_only = true;
      continue;
    }
  }

  std::vector<Case>& cases = Registry();
  std::uint64_t executed = 0;
  std::uint64_t failed_cases = 0;
  for (const Case& entry : cases) {
    const std::string full = entry.suite + "." + entry.name;
    if (!filter.empty() && full.find(filter) == std::string::npos) continue;
    if (list_only) {
      std::printf("%s\n", full.c_str());
      continue;
    }
    g_current = full;
    executed += 1;
    try {
      entry.body();
    } catch (const Failure&) {
      failed_cases += 1;
    } catch (const std::exception& error) {
      g_failures += 1;
      failed_cases += 1;
      std::fprintf(stderr, "FAIL %s: unexpected exception: %s\n", full.c_str(), error.what());
    } catch (...) {
      g_failures += 1;
      failed_cases += 1;
      std::fprintf(stderr, "FAIL %s: unexpected non-standard exception\n", full.c_str());
    }
  }
  if (list_only) return 0;

  std::printf("%s: cases=%llu checks=%llu failures=%llu\n", "summary",
              static_cast<unsigned long long>(executed), static_cast<unsigned long long>(g_checks),
              static_cast<unsigned long long>(g_failures));
  std::fflush(stdout);
  return failed_cases == 0 ? 0 : 1;
}

}  // namespace opp_test

int main(int argc, char** argv) { return opp_test::RunAll(argc, argv); }
