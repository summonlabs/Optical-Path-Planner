#pragma once

// Bounded reads and atomic writes. Every read is bounded and every write is atomic:
// the bytes land in a temporary file in the same directory, are flushed to the
// device, and are then renamed over the destination, so a reader never observes
// a partially written artifact.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "opp/status.hpp"

namespace opp {

[[nodiscard]] Expected<std::string> ReadFileBounded(const std::string& path, std::uint64_t max_bytes);

// Writes bytes atomically. The temporary file name is derived from the target
// name and the process identifier so that two writers cannot collide.
[[nodiscard]] Status WriteFileAtomic(const std::string& path, std::string_view bytes);

[[nodiscard]] Status EnsureDirectory(const std::string& path);
[[nodiscard]] bool FileExists(const std::string& path);
[[nodiscard]] bool DirectoryExists(const std::string& path);
[[nodiscard]] Status RemoveFile(const std::string& path);

// Names (not full paths) of regular files directly inside a directory, sorted.
[[nodiscard]] Expected<std::vector<std::string>> ListDirectoryFiles(const std::string& path);

// Names of directory entries matching a suffix, sorted.
[[nodiscard]] Expected<std::vector<std::string>> ListDirectoryBySuffix(const std::string& path,
                                                                       std::string_view suffix);

[[nodiscard]] Status RenameFile(const std::string& from, const std::string& to);

// Joins two path fragments with the platform separator unless the second is
// already absolute.
[[nodiscard]] std::string JoinPath(std::string_view base, std::string_view leaf);

[[nodiscard]] std::uint64_t ProcessId();

}  // namespace opp
