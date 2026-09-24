#pragma once

// Typed operation status plus a lightweight expected-value wrapper.
//
// The status vocabulary is deliberately wider than success/failure: UNKNOWN,
// UNSUPPORTED, STALE, CONFLICTING, INCOMPLETE, REFUSED and INVALID are distinct
// outcomes and are never collapsed into a false success or a false negative.

#include <cstdint>
#include <string>
#include <utility>

namespace opp {

enum class StatusCode : std::uint32_t {
  Ok = 0,
  // Caller supplied a structurally valid but semantically unacceptable value.
  InvalidArgument,
  // Encoding of the input could not be parsed.
  MalformedInput,
  // A declared bound (count, size, depth) was exceeded.
  LimitExceeded,
  // An identity was declared more than once with incompatible content.
  DuplicateIdentity,
  // A referenced identity does not exist.
  NotFound,
  // Two evidence sources disagree about the same fact.
  ConflictingEvidence,
  // The requested semantics are outside the modelled capability surface.
  Unsupported,
  // Bound evidence is older or newer than the generation the caller requires.
  Stale,
  // The operation targeted a superseded service incarnation or epoch.
  Fenced,
  // The caller cancelled the work.
  Cancelled,
  // A bounded search stopped before exhausting its space.
  Truncated,
  // Stored bytes failed an integrity check.
  IntegrityFailure,
  // Underlying storage or transport failed.
  IoFailure,
  // Refused on policy grounds; retrying the same input will fail the same way.
  Refused,
  // Resource exhaustion (queue, connection or capacity bound).
  Exhausted,
  // Checked arithmetic detected an overflow in a derived quantity.
  Overflow,
  // An invariant of this runtime was violated. Always a defect.
  Internal,
};

const char* StatusCodeName(StatusCode code) noexcept;

struct Status {
  StatusCode code = StatusCode::Ok;
  std::string detail;

  Status() = default;
  Status(StatusCode c, std::string d) : code(c), detail(std::move(d)) {}

  [[nodiscard]] bool ok() const noexcept { return code == StatusCode::Ok; }
  [[nodiscard]] bool failed() const noexcept { return code != StatusCode::Ok; }
  [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
};

inline Status OkStatus() { return Status{}; }

inline Status Failure(StatusCode code, std::string detail) { return Status(code, std::move(detail)); }

// Collapses a status to "the first failure" for control flow that only needs to
// propagate. The detail string is preserved verbatim.
inline Status FirstFailure(const Status& a, const Status& b) { return a.failed() ? a : b; }

template <class T>
class Expected {
 public:
  Expected(Status status) : status_(std::move(status)) {}
  Expected(T value) : status_(), value_(std::move(value)) {}

  [[nodiscard]] bool ok() const noexcept { return status_.ok(); }
  [[nodiscard]] const Status& status() const noexcept { return status_; }
  [[nodiscard]] T& value() & { return value_; }
  [[nodiscard]] const T& value() const& { return value_; }
  [[nodiscard]] T&& value() && { return std::move(value_); }
  // Returns the value when present, otherwise the supplied fallback. Callers
  // that must distinguish absent from present test ok() first.
  [[nodiscard]] T ValueOr(T fallback) const { return status_.ok() ? value_ : std::move(fallback); }

 private:
  Status status_;
  T value_{};
};

}  // namespace opp
