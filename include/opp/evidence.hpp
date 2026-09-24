#pragma once

// Tri-state evidence.
//
// A fact is either KNOWN (a value was published), UNKNOWN (no value was
// published) or CONFLICTING (two sources published incompatible values). The
// planner never substitutes a default for UNKNOWN, and it never picks a winner
// for CONFLICTING. Both of those states make a conclusion unprovable, which the
// planning outcome reports as INDETERMINATE rather than INFEASIBLE.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "opp/ids.hpp"

namespace opp {

enum class Knowledge : std::uint8_t {
  Known = 0,
  Unknown = 1,
  Conflicting = 2,
};

const char* KnowledgeName(Knowledge knowledge) noexcept;

template <class T>
class Evidence {
 public:
  Evidence() = default;

  static Evidence Known(T value) {
    Evidence e;
    e.state_ = Knowledge::Known;
    e.value_ = std::move(value);
    return e;
  }
  static Evidence Unknown() { return Evidence(); }
  static Evidence Conflicting() {
    Evidence e;
    e.state_ = Knowledge::Conflicting;
    return e;
  }

  [[nodiscard]] Knowledge state() const noexcept { return state_; }
  [[nodiscard]] bool HasValue() const noexcept { return state_ == Knowledge::Known; }
  [[nodiscard]] bool IsUnknown() const noexcept { return state_ == Knowledge::Unknown; }
  [[nodiscard]] bool IsConflicting() const noexcept { return state_ == Knowledge::Conflicting; }

  // Precondition: HasValue().
  [[nodiscard]] const T& value() const noexcept { return value_; }

  // Value if known, otherwise the supplied fallback. Callers that need to
  // distinguish "absent" from "present" must test HasValue() first.
  [[nodiscard]] T ValueOr(T fallback) const { return state_ == Knowledge::Known ? value_ : std::move(fallback); }

  friend bool operator==(const Evidence& lhs, const Evidence& rhs) {
    if (lhs.state_ != rhs.state_) return false;
    if (lhs.state_ != Knowledge::Known) return true;
    return lhs.value_ == rhs.value_;
  }

 private:
  Knowledge state_ = Knowledge::Unknown;
  T value_{};
};

// Administrative state of a resource as published by its owner.
enum class AdminState : std::uint8_t {
  Up = 0,
  Down = 1,
  Maintenance = 2,
};

const char* AdminStateName(AdminState state) noexcept;
[[nodiscard]] bool ParseAdminState(std::string_view text, AdminState* out) noexcept;

// Whether a snapshot claims complete knowledge of a resource's adjacency.
enum class Coverage : std::uint8_t {
  // The snapshot enumerates every port and edge of the resource.
  Complete = 0,
  // The snapshot enumerates only some of the resource's ports or edges. A search
  // that reaches a partial resource has an unprovable frontier: absence of a
  // route through it cannot be concluded.
  Partial = 1,
};

const char* CoverageName(Coverage coverage) noexcept;

// An evidence source and the generation it has published into this snapshot.
struct SourceRecord {
  SourceId id;
  Generation generation = 0;
  // Whether the source declares that its contribution is exhaustive for the
  // resources it owns. A partial source makes unexplored neighbourhoods unknown.
  Coverage coverage = Coverage::Complete;
  std::string description;

  friend bool operator==(const SourceRecord&, const SourceRecord&) = default;
  friend auto operator<=>(const SourceRecord&, const SourceRecord&) = default;
};

}  // namespace opp
