#include "opp/fileio.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <system_error>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace opp {
namespace {

std::string TempNameFor(const std::string& path) {
  return path + ".tmp-" + std::to_string(ProcessId());
}

}  // namespace

std::uint64_t ProcessId() {
#if defined(_WIN32)
  return static_cast<std::uint64_t>(GetCurrentProcessId());
#else
  return static_cast<std::uint64_t>(getpid());
#endif
}

std::string JoinPath(std::string_view base, std::string_view leaf) {
  const std::filesystem::path base_path(base);
  const std::filesystem::path leaf_path(leaf);
  if (leaf_path.is_absolute()) return leaf_path.string();
  return (base_path / leaf_path).string();
}

Expected<std::string> ReadFileBounded(const std::string& path, std::uint64_t max_bytes) {
  std::error_code error;
  const auto size = std::filesystem::file_size(path, error);
  if (error) {
    return Failure(StatusCode::NotFound, "cannot stat '" + path + "': " + error.message());
  }
  if (size > max_bytes) {
    return Failure(StatusCode::LimitExceeded, "'" + path + "' is larger than the permitted maximum");
  }
  std::ifstream stream(path, std::ios::binary);
  if (!stream) {
    return Failure(StatusCode::IoFailure, "cannot open '" + path + "' for reading");
  }
  std::string bytes;
  bytes.resize(static_cast<std::size_t>(size));
  if (size > 0) {
    stream.read(bytes.data(), static_cast<std::streamsize>(size));
    if (stream.gcount() != static_cast<std::streamsize>(size)) {
      return Failure(StatusCode::IoFailure, "short read from '" + path + "'");
    }
  }
  return bytes;
}

Status WriteFileAtomic(const std::string& path, std::string_view bytes) {
  const std::string temporary = TempNameFor(path);
  std::FILE* file = std::fopen(temporary.c_str(), "wb");
  if (file == nullptr) {
    return Failure(StatusCode::IoFailure, "cannot create temporary file for '" + path + "'");
  }
  if (!bytes.empty()) {
    const std::size_t written = std::fwrite(bytes.data(), 1, bytes.size(), file);
    if (written != bytes.size()) {
      std::fclose(file);
      std::remove(temporary.c_str());
      return Failure(StatusCode::IoFailure, "short write to temporary file for '" + path + "'");
    }
  }
  if (std::fflush(file) != 0) {
    std::fclose(file);
    std::remove(temporary.c_str());
    return Failure(StatusCode::IoFailure, "flush failed for '" + path + "'");
  }
#if defined(_WIN32)
  if (_commit(_fileno(file)) != 0) {
    std::fclose(file);
    std::remove(temporary.c_str());
    return Failure(StatusCode::IoFailure, "device flush failed for '" + path + "'");
  }
#else
  if (fsync(fileno(file)) != 0) {
    std::fclose(file);
    std::remove(temporary.c_str());
    return Failure(StatusCode::IoFailure, "device flush failed for '" + path + "'");
  }
#endif
  if (std::fclose(file) != 0) {
    std::remove(temporary.c_str());
    return Failure(StatusCode::IoFailure, "close failed for '" + path + "'");
  }
  return RenameFile(temporary, path);
}

Status RenameFile(const std::string& from, const std::string& to) {
#if defined(_WIN32)
  if (MoveFileExW(std::filesystem::path(from).wstring().c_str(),
                  std::filesystem::path(to).wstring().c_str(), MOVEFILE_REPLACE_EXISTING) == 0) {
    return Failure(StatusCode::IoFailure, "cannot rename temporary file into place");
  }
  return OkStatus();
#else
  std::error_code error;
  std::filesystem::rename(from, to, error);
  if (error) {
    return Failure(StatusCode::IoFailure, "cannot rename temporary file into place: " + error.message());
  }
  return OkStatus();
#endif
}

Status EnsureDirectory(const std::string& path) {
  if (path.empty()) {
    return Failure(StatusCode::InvalidArgument, "directory path must not be empty");
  }
  std::error_code error;
  if (std::filesystem::exists(path, error)) {
    if (!std::filesystem::is_directory(path, error)) {
      return Failure(StatusCode::InvalidArgument, "'" + path + "' exists and is not a directory");
    }
    return OkStatus();
  }
  std::filesystem::create_directories(path, error);
  if (error) {
    return Failure(StatusCode::IoFailure, "cannot create directory '" + path + "': " + error.message());
  }
  return OkStatus();
}

bool FileExists(const std::string& path) {
  std::error_code error;
  return std::filesystem::is_regular_file(path, error);
}

bool DirectoryExists(const std::string& path) {
  std::error_code error;
  return std::filesystem::is_directory(path, error);
}

Status RemoveFile(const std::string& path) {
  std::error_code error;
  if (!std::filesystem::exists(path, error)) return OkStatus();
  if (!std::filesystem::remove(path, error) || error) {
    return Failure(StatusCode::IoFailure, "cannot remove '" + path + "': " + error.message());
  }
  return OkStatus();
}

Expected<std::vector<std::string>> ListDirectoryFiles(const std::string& path) {
  std::error_code error;
  if (!std::filesystem::is_directory(path, error)) {
    return Failure(StatusCode::NotFound, "'" + path + "' is not a directory");
  }
  std::vector<std::string> names;
  std::filesystem::directory_iterator iterator(path, error);
  if (error) {
    return Failure(StatusCode::IoFailure, "cannot enumerate '" + path + "': " + error.message());
  }
  for (const auto& entry : iterator) {
    std::error_code entry_error;
    if (entry.is_regular_file(entry_error) && !entry_error) {
      names.push_back(entry.path().filename().string());
    }
  }
  std::sort(names.begin(), names.end());
  return names;
}

Expected<std::vector<std::string>> ListDirectoryBySuffix(const std::string& path, std::string_view suffix) {
  const auto all = ListDirectoryFiles(path);
  if (!all.ok()) return all.status();
  std::vector<std::string> filtered;
  for (const std::string& name : all.value()) {
    if (name.size() >= suffix.size() && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0) {
      filtered.push_back(name);
    }
  }
  return filtered;
}

}  // namespace opp
