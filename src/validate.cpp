#include "opp/validate.hpp"

#include <algorithm>
#include <cmath>
#include <string>

#include "opp/canonical.hpp"
#include "opp/version.hpp"

namespace opp {

const char* PlanValidityName(PlanValidity validity) noexcept {
  switch (validity) {
    case PlanValidity::Valid:
      return "VALID";
    case PlanValidity::Stale:
      return "STALE";
    case PlanValidity::ContentMismatch:
      return "CONTENT_MISMATCH";
    case PlanValidity::MissingEvidence:
      return "MISSING_EVIDENCE";
    case PlanValidity::IntegrityFailure:
      return "INTEGRITY_FAILURE";
    case PlanValidity::Unsupported:
      return "UNSUPPORTED";
    case PlanValidity::Refused:
      return "REFUSED";
    case PlanValidity::NotFresh:
      return "NOT_FRESH";
  }
  return "REFUSED";
}

std::string ValidationReport::ExplainText() const {
  std::string out;
  out += "validity: ";
  out += PlanValidityName(validity);
  out += "\n";
  if (status.failed()) {
    out += "status: ";
    out += StatusCodeName(status.code);
    out += " ";
    out += status.detail;
    out += "\n";
  }
  out += "bound_snapshot_digest: ";
  out += bound_snapshot_digest.ToHex();
  out += "\n";
  out += "current_snapshot_digest: ";
  out += current_snapshot_digest.ToHex();
  out += "\n";
  out += "revalidated: ";
  out += revalidated ? "true" : "false";
  out += "\n";
  for (const SourceMismatch& mismatch : source_mismatches) {
    out += "source_mismatch ";
    out += mismatch.source.str();
    out += " bound=";
    out += FormatU64(mismatch.bound);
    out += " current=";
    out += FormatU64(mismatch.current);
    out += " present=";
    out += mismatch.present ? "true" : "false";
    out += "\n";
  }
  for (const RevalidationFailure& failure : failures) {
    out += "failure step=";
    out += FormatU32(failure.step_index);
    out += " resource=";
    out += ResourceKeyToString(failure.resource);
    out += " reason=";
    out += CutReasonName(failure.reason);
    out += " ";
    out += failure.detail;
    out += "\n";
  }
  return out;
}

ValidationReport ValidatePlanBindings(const PlanArtifact& plan, const TopologySnapshot& snapshot,
                                      const ValidationPolicy& policy) {
  ValidationReport report;
  report.bound_snapshot_digest = plan.snapshot_digest;
  report.current_snapshot_digest = snapshot.digest();

  if (plan.format_version != kPlanFormatVersion || plan.rule_version != kPlanningRuleVersion) {
    report.validity = PlanValidity::Unsupported;
    report.status = Failure(StatusCode::Unsupported,
                            "plan was produced by a format or planning rule revision this runtime does not "
                            "reproduce");
    return report;
  }

  const Status seal = plan.VerifySeal();
  if (seal.failed()) {
    report.validity = PlanValidity::IntegrityFailure;
    report.status = seal;
    return report;
  }

  if (snapshot.freshness() != EvidenceFreshness::Fresh && !policy.accept_restored_evidence) {
    report.validity = PlanValidity::NotFresh;
    report.status = Failure(StatusCode::Stale,
                            "the snapshot was restored from persistence and the caller did not accept restored "
                            "evidence");
    return report;
  }

  bool stale = false;
  for (const SourceBinding& binding : plan.bound_sources) {
    SourceMismatch mismatch;
    mismatch.source = binding.source;
    mismatch.bound = binding.generation;
    mismatch.present = snapshot.HasSource(binding.source);
    mismatch.current = mismatch.present ? snapshot.SourceGeneration(binding.source) : 0;
    if (!mismatch.present || mismatch.current != binding.generation) {
      stale = true;
      report.source_mismatches.push_back(std::move(mismatch));
    }
  }

  // This entry point only compares bindings. Re-deriving the plan's decisions is
  // the job of RevalidatePlan, which owns the policy that asks for it; calling
  // back into it from here would be mutual recursion.
  if (stale) {
    report.validity = PlanValidity::Stale;
    report.status = Failure(StatusCode::Stale,
                            "at least one bound evidence generation no longer matches the current snapshot");
    return report;
  }

  if (!(plan.snapshot_digest == snapshot.digest())) {
    report.validity = PlanValidity::ContentMismatch;
    report.status = Failure(StatusCode::Stale,
                            "source generations match but the snapshot content digest changed");
    return report;
  }

  report.validity = PlanValidity::Valid;
  return report;
}

ValidationReport RevalidatePlan(const PlanArtifact& plan, const TopologySnapshot& snapshot,
                                const ValidationPolicy& policy) {
  // Bindings are compared with a policy that never asks for re-derivation, so
  // this call cannot re-enter RevalidatePlan.
  ValidationPolicy bindings_only;
  bindings_only.accept_restored_evidence = policy.accept_restored_evidence;
  ValidationReport report = ValidatePlanBindings(plan, snapshot, bindings_only);
  if (report.validity != PlanValidity::Valid && !policy.revalidate_on_mismatch) {
    return report;
  }

  report.revalidated = true;
  const SpectrumModel& spectrum = snapshot.spectrum();

  const auto usable_mask = [&spectrum](const Evidence<SlotMask>& blocked) -> SlotMask {
    SlotMask usable = SlotMask::All(spectrum.slot_count);
    if (blocked.HasValue()) {
      for (std::uint16_t slot = 0; slot < spectrum.slot_count; ++slot) {
        if (blocked.value().Test(slot)) usable.Reset(slot);
      }
    }
    return usable.FirstSlotMask(1);
  };

  const auto fail = [&report](std::uint32_t step_index, const ResourceKey& resource, CutReason reason,
                              const std::string& detail) {
    RevalidationFailure failure;
    failure.step_index = step_index;
    failure.resource = resource;
    failure.reason = reason;
    failure.detail = detail;
    report.failures.push_back(std::move(failure));
  };

  for (const PlanStep& step : plan.steps) {
    switch (step.resource.kind()) {
      case ResourceKind::Port: {
        const std::size_t colon = step.resource.text().find(':');
        if (colon == std::string::npos) {
          fail(step.index, step.resource, CutReason::None, "malformed port resource key");
          break;
        }
        const auto node = NodeId::Parse(std::string_view(step.resource.text()).substr(0, colon));
        const auto port = PortId::Parse(std::string_view(step.resource.text()).substr(colon + 1));
        if (!node.ok() || !port.ok()) {
          fail(step.index, step.resource, CutReason::None, "malformed port resource key");
          break;
        }
        const PortRecord* record = snapshot.FindPort(PortKey{node.value(), port.value()});
        if (record == nullptr) {
          fail(step.index, step.resource, CutReason::UnresolvedReference, "port is absent from the snapshot");
          break;
        }
        if (!record->admin.HasValue() || record->admin.value() != AdminState::Up) {
          fail(step.index, step.resource, CutReason::DestinationAdminDown,
               "port is not published as administratively up");
        }
        break;
      }
      case ResourceKind::Node: {
        const auto id = NodeId::Parse(step.resource.text());
        if (!id.ok()) {
          fail(step.index, step.resource, CutReason::None, "malformed node resource key");
          break;
        }
        const NodeRecord* record = snapshot.FindNode(id.value());
        if (record == nullptr) {
          fail(step.index, step.resource, CutReason::UnresolvedReference, "node is absent from the snapshot");
          break;
        }
        if (!record->admin.HasValue() || record->admin.value() != AdminState::Up) {
          fail(step.index, step.resource, CutReason::DestinationAdminDown,
               "node is not published as administratively up");
        }
        break;
      }
      case ResourceKind::Span: {
        const auto id = SpanId::Parse(step.resource.text());
        if (!id.ok()) {
          fail(step.index, step.resource, CutReason::None, "malformed span resource key");
          break;
        }
        const SpanRecord* record = nullptr;
        for (const SpanRecord& candidate : snapshot.spans()) {
          if (candidate.id == id.value()) {
            record = &candidate;
            break;
          }
        }
        if (record == nullptr) {
          fail(step.index, step.resource, CutReason::UnresolvedReference, "span is absent from the snapshot");
          break;
        }
        if (!record->admin.HasValue() || record->admin.value() != AdminState::Up) {
          fail(step.index, step.resource, CutReason::SpanAdminDown,
               "span is not published as administratively up");
          break;
        }
        const PlanReservation* reservation = nullptr;
        for (const PlanReservation& candidate : plan.reservations) {
          if (candidate.resource == step.resource) {
            reservation = &candidate;
            break;
          }
        }
        if (reservation == nullptr) {
          fail(step.index, step.resource, CutReason::None, "plan carries no spectrum requirement for this span");
          break;
        }
        const SlotMask usable = usable_mask(record->blocked_slots);
        SlotMask wanted;
        for (std::uint32_t offset = 0; offset < reservation->channel.width_slots; ++offset) {
          wanted.Set(static_cast<std::uint16_t>(reservation->channel.first_slot + offset));
        }
        if (!wanted.IsSubsetOf(usable)) {
          fail(step.index, step.resource, CutReason::PortSpectrumEmpty,
               "the recorded channel is no longer inside the span's usable spectrum");
        }
        break;
      }
      case ResourceKind::CrossConnect: {
        const auto id = CrossConnectId::Parse(step.resource.text());
        if (!id.ok()) {
          fail(step.index, step.resource, CutReason::None, "malformed cross-connect resource key");
          break;
        }
        const CrossConnectRecord* record = nullptr;
        for (const CrossConnectRecord& candidate : snapshot.cross_connects()) {
          if (candidate.id == id.value()) {
            record = &candidate;
            break;
          }
        }
        if (record == nullptr) {
          fail(step.index, step.resource, CutReason::UnresolvedReference,
               "cross-connect is absent from the snapshot");
          break;
        }
        if (!record->admin.HasValue() || record->admin.value() != AdminState::Up) {
          fail(step.index, step.resource, CutReason::CrossConnectAdminDown,
               "cross-connect is not published as administratively up");
        }
        break;
      }
      case ResourceKind::FailureDomain:
      case ResourceKind::ReachProfile:
      case ResourceKind::Channel:
      case ResourceKind::Source:
        break;
    }
  }

  // Recompute the transparent-section accounting from the recorded span uses and
  // compare it with what the plan claims.
  for (const PlanSegment& segment : plan.segments) {
    std::uint64_t distance = 0;
    double loss = 0.0;
    double osnr_inverse = 0.0;
    std::uint32_t spans = 0;
    for (const PlanSpanUse& use : segment.spans) {
      const SpanRecord* record = nullptr;
      for (const SpanRecord& candidate : snapshot.spans()) {
        if (candidate.id == use.id) {
          record = &candidate;
          break;
        }
      }
      if (record == nullptr) continue;
      if (record->length_m.HasValue()) distance += record->length_m.value();
      if (record->loss_db.HasValue()) loss += record->loss_db.value();
      if (record->osnr_db.HasValue()) osnr_inverse += std::pow(10.0, -record->osnr_db.value() / 10.0);
      spans += 1;
    }
    const double osnr = osnr_inverse <= 0.0 ? 0.0 : -10.0 * std::log10(osnr_inverse);
    if (distance != segment.distance_m || spans != segment.span_count ||
        std::fabs(loss - segment.loss_db) > 1.0e-9 || std::fabs(osnr - segment.osnr_db) > 1.0e-9) {
      fail(0, ResourceKey::ForReachProfile(segment.profile), CutReason::None,
           "segment accounting does not reproduce against the current snapshot");
    }
  }

  if (report.failures.empty()) {
    if (report.validity != PlanValidity::Valid) {
      // The bindings were stale but every decision still reproduces.
      report.status = Failure(StatusCode::Stale,
                              "bound generations changed, but every plan decision still reproduces against the "
                              "current snapshot");
    }
  } else if (report.validity == PlanValidity::Valid) {
    report.validity = PlanValidity::MissingEvidence;
    report.status = Failure(StatusCode::Internal,
                            "plan decisions no longer reproduce against the snapshot it is bound to");
  } else {
    report.status = Failure(StatusCode::Stale, "plan decisions no longer reproduce against the current snapshot");
  }
  return report;
}

}  // namespace opp
