#include "opp/version.hpp"

#include <string>

namespace opp {
namespace {

constexpr const char* kVersion = "1.0.0";
constexpr const char* kLibraryName = "OpticalPathPlanner";

}  // namespace

const char* VersionString() { return kVersion; }

const char* LibraryName() { return kLibraryName; }

const char* BuildIdentification() {
#if defined(_MSC_VER)
  static const std::string text = std::string("msvc-") + std::to_string(_MSC_VER) + "/c++" +
                                  std::to_string(__cplusplus);
#elif defined(__clang__)
  static const std::string text = std::string("clang-") + __clang_version__ + "/c++" +
                                  std::to_string(__cplusplus);
#elif defined(__GNUC__)
  static const std::string text = std::string("gcc-") + __VERSION__ + "/c++" + std::to_string(__cplusplus);
#else
  static const std::string text = std::string("unknown/c++") + std::to_string(__cplusplus);
#endif
  return text.c_str();
}

}  // namespace opp
