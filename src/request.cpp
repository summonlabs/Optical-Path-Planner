#include "opp/request.hpp"

#include <algorithm>

#include "opp/canonical.hpp"

namespace opp {

Status PlanningRequest::Validate() const {
  if (format_version != kRequestFormatVersion) {
    return Failure(StatusCode::Unsupported,
                   "request format revision " + std::to_string(format_version) + " is not supported");
  }
  if (id.empty()) {
    return Failure(StatusCode::InvalidArgument, "request id must not be empty");
  }
  if (source.node.empty() || source.port.empty()) {
    return Failure(StatusCode::InvalidArgument, "source must name both a node and a port");
  }
  if (destination.node.empty() || destination.port.empty()) {
    return Failure(StatusCode::InvalidArgument, "destination must name both a node and a port");
  }
  if (source == destination) {
    return Failure(StatusCode::InvalidArgument, "source and destination must differ");
  }
  if (channel_width_slots == 0) {
    return Failure(StatusCode::InvalidArgument, "channel width must be at least one slot");
  }
  if (channel_width_slots > kMaxSpectrumSlots) {
    return Failure(StatusCode::InvalidArgument, "channel width exceeds the supported spectrum capacity");
  }
  if (max_candidates == 0) {
    return Failure(StatusCode::InvalidArgument, "max_candidates must be at least 1");
  }
  if (max_candidates > kMaxCandidates) {
    return Failure(StatusCode::LimitExceeded,
                   "max_candidates exceeds the supported maximum of " + std::to_string(kMaxCandidates));
  }
  if (max_regenerations > kMaxRequestedRegenerations) {
    return Failure(StatusCode::LimitExceeded, "max_regenerations exceeds the supported maximum");
  }
  if (max_hops == 0) {
    return Failure(StatusCode::InvalidArgument, "max_hops must be at least 1");
  }
  if (max_hops > kMaxRequestedHops) {
    return Failure(StatusCode::LimitExceeded, "max_hops exceeds the supported maximum");
  }
  if (max_search_expansions == 0 || max_search_expansions > kMaxSearchExpansionsCeiling) {
    return Failure(StatusCode::LimitExceeded, "max_search_expansions must be within the supported range");
  }
  if (max_search_labels == 0 || max_search_labels > kMaxSearchLabelsCeiling) {
    return Failure(StatusCode::LimitExceeded, "max_search_labels must be within the supported range");
  }
  if (required_source_generations.size() > kMaxRequiredGenerations) {
    return Failure(StatusCode::LimitExceeded, "required_source_generations exceeds the supported number of entries");
  }
  const Status constraint_status = this->constraints.Validate();
  if (constraint_status.failed()) return constraint_status;

  // Semantics the model deliberately does not implement. A caller asking for
  // them must learn the boundary instead of receiving a plan computed under
  // different rules.
  if (this->constraints.require_spectrum_continuity_across_regeneration) {
    return Failure(StatusCode::Unsupported,
                   "this model restarts the transparent segment at a regeneration, so spectrum continuity "
                   "across a regeneration cannot be required");
  }
  if (this->constraints.allow_repeated_resources) {
    return Failure(StatusCode::Unsupported,
                   "this model restricts a candidate to a resource-simple route; repeated resources are not "
                   "modelled");
  }
  return OkStatus();
}

}  // namespace opp
