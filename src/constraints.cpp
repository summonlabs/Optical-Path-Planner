#include "opp/constraints.hpp"

#include <algorithm>
#include <string>

#include "opp/canonical.hpp"
#include "opp/limits.hpp"

namespace opp {
namespace {

template <class T>
Status RequireSortedUnique(std::vector<T>& values, const char* what) {
  if (values.size() > kMaxExclusionEntries) {
    return Failure(StatusCode::LimitExceeded, std::string(what) + " exceeds the maximum number of entries");
  }
  std::sort(values.begin(), values.end());
  if (std::adjacent_find(values.begin(), values.end()) != values.end()) {
    return Failure(StatusCode::DuplicateIdentity, std::string(what) + " contains a duplicate entry");
  }
  return OkStatus();
}

Status ValidateOptionalNonNegative(const std::optional<double>& value, const char* what) {
  if (value.has_value() && (!(value.value() >= 0.0) || value.value() > 1.0e9)) {
    return Failure(StatusCode::InvalidArgument, std::string(what) + " must be a finite value in [0, 1e9]");
  }
  return OkStatus();
}

}  // namespace

const char* DisjointnessName(Disjointness value) noexcept {
  switch (value) {
    case Disjointness::None:
      return "none";
    case Disjointness::Node:
      return "node";
    case Disjointness::Span:
      return "span";
    case Disjointness::FailureDomain:
      return "domain";
  }
  return "none";
}

bool ParseDisjointness(std::string_view text, Disjointness* out) noexcept {
  if (out == nullptr) return false;
  if (text == "none") {
    *out = Disjointness::None;
    return true;
  }
  if (text == "node") {
    *out = Disjointness::Node;
    return true;
  }
  if (text == "span") {
    *out = Disjointness::Span;
    return true;
  }
  if (text == "domain") {
    *out = Disjointness::FailureDomain;
    return true;
  }
  return false;
}

Status ConstraintSet::Validate() const {
  std::vector<NodeId> nodes = excluded_nodes;
  Status status = RequireSortedUnique(nodes, "excluded_nodes");
  if (status.failed()) return status;

  std::vector<PortKey> ports = excluded_ports;
  status = RequireSortedUnique(ports, "excluded_ports");
  if (status.failed()) return status;

  std::vector<SpanId> spans = excluded_spans;
  status = RequireSortedUnique(spans, "excluded_spans");
  if (status.failed()) return status;

  std::vector<CrossConnectId> cross_connects = excluded_cross_connects;
  status = RequireSortedUnique(cross_connects, "excluded_cross_connects");
  if (status.failed()) return status;

  std::vector<FailureDomainId> domains = excluded_failure_domains;
  status = RequireSortedUnique(domains, "excluded_failure_domains");
  if (status.failed()) return status;

  if (max_members_per_failure_domain.size() > kMaxDomainMemberLimits) {
    return Failure(StatusCode::LimitExceeded, "max_members_per_failure_domain exceeds the maximum number of entries");
  }
  for (const auto& entry : max_members_per_failure_domain) {
    if (entry.second == 0) {
      return Failure(StatusCode::InvalidArgument,
                     "max_members_per_failure_domain for '" + entry.first.str() + "' must be at least 1");
    }
  }

  if (max_total_span_count.has_value() && max_total_span_count.value() == 0) {
    return Failure(StatusCode::InvalidArgument, "max_total_span_count must be at least 1");
  }

  status = ValidateOptionalNonNegative(max_total_loss_db, "max_total_loss_db");
  if (status.failed()) return status;
  status = ValidateOptionalNonNegative(min_segment_osnr_db, "min_segment_osnr_db");
  if (status.failed()) return status;

  return OkStatus();
}

}  // namespace opp
