#pragma once

// Minimal deterministic test harness. No external dependency, no timeouts, no
// fixed ports, no hidden global state beyond the case registry. Cases run in
// registration order so that a failure is reproducible from the case name alone.

#include <cstdint>
#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace opp_test {

struct Case {
  std::string suite;
  std::string name;
  std::function<void()> body;
};

struct Failure {
  std::string message;
};

extern std::uint64_t g_checks;
extern std::uint64_t g_failures;
extern std::string g_current;

std::vector<Case>& Registry();

struct Registrar {
  Registrar(const char* suite, const char* name, std::function<void()> body);
};

[[noreturn]] void Fail(const char* file, int line, const std::string& message);

// Comparison indirection keeps the compiler front end from seeing a
// syntactically constant condition under /W4 /WX.
template <class Lhs, class Rhs>
bool EqualValues(const Lhs& lhs, const Rhs& rhs) {
  return lhs == rhs;
}

// Runs every registered case, honouring an optional name filter. Returns the
// process exit code.
int RunAll(int argc, char** argv);

}  // namespace opp_test

#define OPP_TEST(suite_name, case_name)                                                            static void suite_name##_##case_name##_body();                                                   static const ::opp_test::Registrar suite_name##_##case_name##_registrar(                             #suite_name, #case_name, suite_name##_##case_name##_body);                                   static void suite_name##_##case_name##_body()

#define OPP_CHECK(condition)                                                                       do {                                                                                               ::opp_test::g_checks += 1;                                                                       if (!(condition)) {                                                                                ::opp_test::Fail(__FILE__, __LINE__, "check failed: " #condition);                             }                                                                                              } while (false)

#define OPP_CHECK_MSG(condition, message)                                                          do {                                                                                               ::opp_test::g_checks += 1;                                                                       if (!(condition)) {                                                                                ::opp_test::Fail(__FILE__, __LINE__,                                                                              std::string("check failed: " #condition " :: ") + (message));                 }                                                                                              } while (false)

#define OPP_REQUIRE(condition)                                                                     do {                                                                                               ::opp_test::g_checks += 1;                                                                       if (!(condition)) {                                                                                ::opp_test::Fail(__FILE__, __LINE__, "requirement failed: " #condition);                          return;                                                                                        }                                                                                              } while (false)

#define OPP_REQUIRE_MSG(condition, message)                                                      \
  do {                                                                                           \
    ::opp_test::g_checks += 1;                                                                   \
    if (!(condition)) {                                                                          \
      ::opp_test::Fail(__FILE__, __LINE__,                                                       \
                       std::string("requirement failed: " #condition " :: ") + (message));        \
      return;                                                                                    \
    }                                                                                            \
  } while (false)

// Operands are held by value: binding them by reference would dangle for
// expressions such as optional.value() that return a reference into a temporary.
#define OPP_CHECK_EQ(lhs, rhs)                                                                     do {                                                                                               ::opp_test::g_checks += 1;                                                                       const auto opp_lhs = (lhs);                                                                      const auto opp_rhs = (rhs);                                                                      if (!::opp_test::EqualValues(opp_lhs, opp_rhs)) {                                                  ::opp_test::Fail(__FILE__, __LINE__, "equality check failed: " #lhs " == " #rhs);               }                                                                                              } while (false)
