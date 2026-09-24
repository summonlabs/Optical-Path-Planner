#pragma once

// Canonical text encoding of a planning request and of a validation policy.

#include <string>
#include <string_view>

#include "opp/request.hpp"
#include "opp/status.hpp"
#include "opp/validate.hpp"

namespace opp {

inline constexpr const char* kRequestMagic = "OPP-REQUEST";
inline constexpr const char* kRequestDigestDomain = "OPP-REQUEST-v1";

[[nodiscard]] std::string RequestToText(const PlanningRequest& request);
[[nodiscard]] Expected<PlanningRequest> ParseRequestText(std::string_view text);

[[nodiscard]] std::string ValidationPolicyToText(const ValidationPolicy& policy);
[[nodiscard]] Expected<ValidationPolicy> ParseValidationPolicyText(std::string_view text);

}  // namespace opp
