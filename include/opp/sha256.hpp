#pragma once

// SHA-256 used for evidence digests, plan sealing, store integrity and the
// framed transport's payload checks. Implemented here so the runtime has no
// external dependency and produces identical digests on every platform.

#include <cstdint>
#include <string>
#include <string_view>

#include "opp/ids.hpp"

namespace opp {

class Sha256 {
 public:
  static constexpr std::size_t kDigestBytes = 32;
  static constexpr std::size_t kBlockBytes = 64;

  Sha256() = default;

  void Update(const void* data, std::size_t size);
  void Update(std::string_view text) { Update(text.data(), text.size()); }

  // Finalises and returns the digest. The object must not be updated again
  // unless Reset() is called first; Finalize() is idempotent for a fixed state.
  [[nodiscard]] Digest256 Finalize() const;

  void Reset();

  // Convenience one-shot helpers.
  static Digest256 Of(const void* data, std::size_t size);
  static Digest256 Of(std::string_view text);

 private:
  void Compress(const std::uint8_t block[kBlockBytes]);

  std::uint32_t state_[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                             0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  std::uint8_t buffer_[kBlockBytes] = {};
  std::uint64_t total_bytes_ = 0;
  std::size_t buffered_ = 0;
};

// Self-test against the published NIST vectors. Returns false on mismatch; used
// by the CLI's "selftest" command and by the test suites.
[[nodiscard]] bool Sha256SelfTest(std::string* detail);

}  // namespace opp
