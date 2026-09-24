#include "opp/evidence.hpp"

#include <string_view>

namespace opp {

const char* KnowledgeName(Knowledge knowledge) noexcept {
  switch (knowledge) {
    case Knowledge::Known:
      return "known";
    case Knowledge::Unknown:
      return "unknown";
    case Knowledge::Conflicting:
      return "conflicting";
  }
  return "unknown";
}

const char* AdminStateName(AdminState state) noexcept {
  switch (state) {
    case AdminState::Up:
      return "up";
    case AdminState::Down:
      return "down";
    case AdminState::Maintenance:
      return "maintenance";
  }
  return "unknown";
}

bool ParseAdminState(std::string_view text, AdminState* out) noexcept {
  if (out == nullptr) return false;
  if (text == "up") {
    *out = AdminState::Up;
    return true;
  }
  if (text == "down") {
    *out = AdminState::Down;
    return true;
  }
  if (text == "maintenance") {
    *out = AdminState::Maintenance;
    return true;
  }
  return false;
}

const char* CoverageName(Coverage coverage) noexcept {
  switch (coverage) {
    case Coverage::Complete:
      return "complete";
    case Coverage::Partial:
      return "partial";
  }
  return "partial";
}

}  // namespace opp
