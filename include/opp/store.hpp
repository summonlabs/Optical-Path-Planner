#pragma once

// Immutable plan artifact persistence.
//
// The store is content addressed: a file name is the digest of the artifact it
// holds. Writes go to a temporary file that is flushed and renamed into place, so
// a reader never observes a partially written artifact. Every read re-verifies
// the artifact seal and the file checksum; a mismatch is reported as an integrity
// failure and the file is never silently repaired or overwritten.
//
// The store is bounded: it refuses to grow past max_plans rather than evicting
// artifacts behind the caller's back. It stores no live evidence and confers no
// freshness on anything it returns.

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "opp/plan.hpp"
#include "opp/status.hpp"

namespace opp {

inline constexpr const char* kStoreDirectoryName = "plans";
inline constexpr const char* kStoreFileSuffix = ".oppplan";
inline constexpr const char* kStoreTempSuffix = ".opptmp";
inline constexpr const char* kStoreFileMagic = "OPPFILE1";

struct StoreOptions {
  // Directory that holds the plan files. Created when missing.
  std::string root;
  // Hard upper bound on retained artifacts. Put() fails with Exhausted once the
  // bound is reached; nothing is evicted implicitly.
  std::uint32_t max_plans = 4096;
  // When true, Put() verifies an existing file with the same digest instead of
  // treating it as a conflict.
  bool verify_existing = true;
};

struct StoreEntry {
  Digest256 digest{};
  std::uint64_t bytes = 0;
  RequestId request_id;
  std::string file_name;
};

class PlanStore {
 public:
  // Opens (and creates when needed) a store. Stale temporary files left behind by
  // an interrupted write are removed during the open; that is the only repair the
  // store performs.
  static Expected<std::shared_ptr<PlanStore>> Open(StoreOptions options);

  PlanStore(const PlanStore&) = delete;
  PlanStore& operator=(const PlanStore&) = delete;

  [[nodiscard]] const StoreOptions& options() const noexcept { return options_; }

  // Stores a sealed artifact. Idempotent for identical content.
  [[nodiscard]] Status Put(const PlanArtifact& plan);

  [[nodiscard]] Expected<PlanArtifact> Get(const Digest256& digest) const;
  [[nodiscard]] Expected<PlanArtifact> GetByHex(std::string_view hex) const;

  [[nodiscard]] bool Contains(const Digest256& digest) const;

  // Validates and returns every artifact in the store, sorted by digest. Files
  // that fail validation are reported in rejected with their file names.
  [[nodiscard]] Status List(std::vector<StoreEntry>* entries, std::vector<std::string>* rejected) const;

  [[nodiscard]] Status Remove(const Digest256& digest);

  [[nodiscard]] std::uint32_t Count() const;

  [[nodiscard]] std::string PathFor(const Digest256& digest) const;

 private:
  explicit PlanStore(StoreOptions options) : options_(std::move(options)) {}

  [[nodiscard]] Status LoadLocked(const std::string& path, PlanArtifact* out, Digest256* digest) const;
  [[nodiscard]] Status ScanLocked(std::vector<std::string>* names) const;
  void CleanTemporariesLocked();

  StoreOptions options_;
  mutable std::mutex mutex_;
};

// Encodes an artifact as the exact bytes a store file holds: magic, format
// revision, payload length, payload, checksum. Bounded by kMaxPlanArtifactBytes.
[[nodiscard]] Expected<std::string> EncodeStoreFile(const PlanArtifact& plan);

// Decodes and verifies a store file. Rejects truncation, trailing bytes, wrong
// magic, wrong revision and checksum mismatches with distinct status codes.
[[nodiscard]] Expected<PlanArtifact> DecodeStoreFile(std::string_view bytes);

}  // namespace opp
