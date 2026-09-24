#include "opp/status.hpp"

namespace opp {

const char* StatusCodeName(StatusCode code) noexcept {
  switch (code) {
    case StatusCode::Ok:
      return "OK";
    case StatusCode::InvalidArgument:
      return "INVALID_ARGUMENT";
    case StatusCode::MalformedInput:
      return "MALFORMED_INPUT";
    case StatusCode::LimitExceeded:
      return "LIMIT_EXCEEDED";
    case StatusCode::DuplicateIdentity:
      return "DUPLICATE_IDENTITY";
    case StatusCode::NotFound:
      return "NOT_FOUND";
    case StatusCode::ConflictingEvidence:
      return "CONFLICTING_EVIDENCE";
    case StatusCode::Unsupported:
      return "UNSUPPORTED";
    case StatusCode::Stale:
      return "STALE";
    case StatusCode::Fenced:
      return "FENCED";
    case StatusCode::Cancelled:
      return "CANCELLED";
    case StatusCode::Truncated:
      return "TRUNCATED";
    case StatusCode::IntegrityFailure:
      return "INTEGRITY_FAILURE";
    case StatusCode::IoFailure:
      return "IO_FAILURE";
    case StatusCode::Refused:
      return "REFUSED";
    case StatusCode::Exhausted:
      return "EXHAUSTED";
    case StatusCode::Overflow:
      return "OVERFLOW";
    case StatusCode::Internal:
      return "INTERNAL";
  }
  return "UNKNOWN_STATUS";
}

}  // namespace opp
