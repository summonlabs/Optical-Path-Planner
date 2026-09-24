#include "opp/store.hpp"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "opp/fileio.hpp"
#include "opp/canonical.hpp"
#include "opp/limits.hpp"
#include "opp/sha256.hpp"
#include "opp/version.hpp"

namespace opp {
namespace {

constexpr std::size_t kHeaderBytes = 8 + 4 + 4 + 8;

std::string FileNameFor(const Digest256& digest) {
  return digest.ToHex() + kStoreFileSuffix;
}

bool HasSuffix(const std::string& name, std::string_view suffix) {
  return name.size() >= suffix.size() && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0;
}

}  // namespace

Expected<std::string> EncodeStoreFile(const PlanArtifact& plan) {
  const Status seal = plan.VerifySeal();
  if (seal.failed()) return seal;
  const std::string payload = plan.CanonicalBytes();
  if (payload.size() > kMaxStoreFileBytes) {
    return Failure(StatusCode::LimitExceeded, "plan artifact exceeds the store file bound");
  }
  std::string bytes;
  bytes.reserve(kHeaderBytes + payload.size() + 32);
  bytes.append(kStoreFileMagic, 8);
  ByteWriter header;
  header.U32(kStoreFormatVersion);
  header.U32(0);
  header.U64(static_cast<std::uint64_t>(payload.size()));
  bytes += header.buffer();
  bytes += payload;
  Sha256 hasher;
  hasher.Update(bytes);
  const Digest256 checksum = hasher.Finalize();
  bytes.append(reinterpret_cast<const char*>(checksum.bytes.data()), checksum.bytes.size());
  return bytes;
}

Expected<PlanArtifact> DecodeStoreFile(std::string_view bytes) {
  if (bytes.size() < kHeaderBytes + 32) {
    return Failure(StatusCode::Truncated, "store file is shorter than its header and checksum");
  }
  if (bytes.compare(0, 8, kStoreFileMagic, 8) != 0) {
    return Failure(StatusCode::MalformedInput, "store file magic is not recognised");
  }
  ByteReader header(bytes.substr(8, kHeaderBytes - 8));
  const auto version = header.U32();
  if (!version.ok()) return version.status();
  if (version.value() != kStoreFormatVersion) {
    return Failure(StatusCode::Unsupported, "store file revision is not supported by this runtime");
  }
  const auto reserved = header.U32();
  if (!reserved.ok()) return reserved.status();
  if (reserved.value() != 0) {
    return Failure(StatusCode::MalformedInput, "store file reserved field must be zero");
  }
  const auto length = header.U64();
  if (!length.ok()) return length.status();
  if (length.value() > kMaxStoreFileBytes) {
    return Failure(StatusCode::LimitExceeded, "store file declares a payload larger than the bound");
  }
  const std::uint64_t expected_total = static_cast<std::uint64_t>(kHeaderBytes) + length.value() + 32u;
  if (static_cast<std::uint64_t>(bytes.size()) != expected_total) {
    return Failure(StatusCode::Truncated, "store file length does not match its declared payload size");
  }
  const std::string_view payload = bytes.substr(kHeaderBytes, static_cast<std::size_t>(length.value()));
  const std::string_view trailer = bytes.substr(kHeaderBytes + static_cast<std::size_t>(length.value()), 32);
  Sha256 hasher;
  hasher.Update(bytes.substr(0, kHeaderBytes + static_cast<std::size_t>(length.value())));
  const Digest256 checksum = hasher.Finalize();
  const std::string_view computed(reinterpret_cast<const char*>(checksum.bytes.data()), checksum.bytes.size());
  if (computed != trailer) {
    return Failure(StatusCode::IntegrityFailure, "store file checksum does not match its content");
  }
  return ParsePlanArtifact(payload);
}

Expected<std::shared_ptr<PlanStore>> PlanStore::Open(StoreOptions options) {
  if (options.root.empty()) {
    return Failure(StatusCode::InvalidArgument, "store root must not be empty");
  }
  if (options.max_plans == 0 || options.max_plans > kMaxStoredPlans) {
    return Failure(StatusCode::InvalidArgument, "store max_plans is outside the supported range");
  }
  Status status = EnsureDirectory(options.root);
  if (status.failed()) return status;
  status = EnsureDirectory(JoinPath(options.root, kStoreDirectoryName));
  if (status.failed()) return status;
  auto store = std::shared_ptr<PlanStore>(new PlanStore(std::move(options)));
  std::lock_guard<std::mutex> guard(store->mutex_);
  store->CleanTemporariesLocked();
  return store;
}

std::string PlanStore::PathFor(const Digest256& digest) const {
  return JoinPath(JoinPath(options_.root, kStoreDirectoryName), FileNameFor(digest));
}

void PlanStore::CleanTemporariesLocked() {
  const auto names = ListDirectoryFiles(JoinPath(options_.root, kStoreDirectoryName));
  if (!names.ok()) return;
  for (const std::string& name : names.value()) {
    if (!HasSuffix(name, ".tmp") && !HasSuffix(name, kStoreTempSuffix)) continue;
    const Status removed = RemoveFile(JoinPath(JoinPath(options_.root, kStoreDirectoryName), name));
    (void)removed;
  }
}

Status PlanStore::ScanLocked(std::vector<std::string>* names) const {
  const auto listed = ListDirectoryBySuffix(JoinPath(options_.root, kStoreDirectoryName), kStoreFileSuffix);
  if (!listed.ok()) return listed.status();
  *names = listed.value();
  return OkStatus();
}

Status PlanStore::LoadLocked(const std::string& path, PlanArtifact* out, Digest256* digest) const {
  const auto bytes = ReadFileBounded(path, kMaxStoreFileBytes);
  if (!bytes.ok()) return bytes.status();
  const auto plan = DecodeStoreFile(bytes.value());
  if (!plan.ok()) return plan.status();
  *out = plan.value();
  *digest = out->digest;
  return OkStatus();
}

Status PlanStore::Put(const PlanArtifact& plan) {
  std::lock_guard<std::mutex> guard(mutex_);
  const auto encoded = EncodeStoreFile(plan);
  if (!encoded.ok()) return encoded.status();

  const std::string path = PathFor(plan.digest);
  if (FileExists(path)) {
    if (!options_.verify_existing) {
      return Failure(StatusCode::Refused, "an artifact with this digest already exists in the store");
    }
    const auto existing = ReadFileBounded(path, kMaxStoreFileBytes);
    if (!existing.ok()) return existing.status();
    if (existing.value() != encoded.value()) {
      return Failure(StatusCode::IntegrityFailure,
                     "an artifact with this digest exists in the store but its content differs");
    }
    return OkStatus();
  }

  std::vector<std::string> names;
  const Status scanned = ScanLocked(&names);
  if (scanned.failed()) return scanned;
  if (names.size() >= options_.max_plans) {
    return Failure(StatusCode::Exhausted, "the plan store has reached its configured capacity");
  }
  return WriteFileAtomic(path, encoded.value());
}

Expected<PlanArtifact> PlanStore::Get(const Digest256& digest) const {
  std::lock_guard<std::mutex> guard(mutex_);
  const std::string path = PathFor(digest);
  if (!FileExists(path)) {
    return Failure(StatusCode::NotFound, "no stored artifact has digest " + digest.ToHex());
  }
  PlanArtifact plan;
  Digest256 actual{};
  const Status status = LoadLocked(path, &plan, &actual);
  if (status.failed()) return status;
  if (!(actual == digest)) {
    return Failure(StatusCode::IntegrityFailure,
                   "stored artifact content does not match the digest in its file name");
  }
  return plan;
}

Expected<PlanArtifact> PlanStore::GetByHex(std::string_view hex) const {
  const auto digest = Digest256::FromHex(hex);
  if (!digest.ok()) return digest.status();
  return Get(digest.value());
}

bool PlanStore::Contains(const Digest256& digest) const {
  std::lock_guard<std::mutex> guard(mutex_);
  return FileExists(PathFor(digest));
}

Status PlanStore::List(std::vector<StoreEntry>* entries, std::vector<std::string>* rejected) const {
  std::lock_guard<std::mutex> guard(mutex_);
  std::vector<std::string> names;
  const Status scanned = ScanLocked(&names);
  if (scanned.failed()) return scanned;
  std::vector<StoreEntry> collected;
  for (const std::string& name : names) {
    const std::string path = JoinPath(JoinPath(options_.root, kStoreDirectoryName), name);
    PlanArtifact plan;
    Digest256 digest{};
    const Status status = LoadLocked(path, &plan, &digest);
    if (status.failed()) {
      if (rejected != nullptr) rejected->push_back(name);
      continue;
    }
    if (name != FileNameFor(digest)) {
      if (rejected != nullptr) rejected->push_back(name);
      continue;
    }
    StoreEntry entry;
    entry.digest = digest;
    entry.request_id = plan.request_id;
    entry.file_name = name;
    const auto bytes = ReadFileBounded(path, kMaxStoreFileBytes);
    entry.bytes = bytes.ok() ? static_cast<std::uint64_t>(bytes.value().size()) : 0;
    collected.push_back(std::move(entry));
  }
  std::sort(collected.begin(), collected.end(), [](const StoreEntry& lhs, const StoreEntry& rhs) {
    return lhs.digest < rhs.digest;
  });
  *entries = std::move(collected);
  return OkStatus();
}

Status PlanStore::Remove(const Digest256& digest) {
  std::lock_guard<std::mutex> guard(mutex_);
  const std::string path = PathFor(digest);
  if (!FileExists(path)) {
    return Failure(StatusCode::NotFound, "no stored artifact has digest " + digest.ToHex());
  }
  return RemoveFile(path);
}

std::uint32_t PlanStore::Count() const {
  std::lock_guard<std::mutex> guard(mutex_);
  std::vector<std::string> names;
  if (ScanLocked(&names).failed()) return 0;
  return static_cast<std::uint32_t>(names.size());
}

}  // namespace opp
