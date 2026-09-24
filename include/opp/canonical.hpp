#pragma once

// Canonical encoding primitives.
//
// The same encoding is used for snapshot digests, plan digests, persisted text
// files and wire payloads. It is deliberately strict: a token is either exactly
// representable or it is percent-escaped, numbers round-trip bit-exactly, and
// anything the grammar does not cover is rejected instead of guessed at.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "opp/ids.hpp"
#include "opp/status.hpp"

namespace opp {

// ---------------------------------------------------------------------------
// Checked arithmetic. Every externally derived size or cost goes through these.
// ---------------------------------------------------------------------------
[[nodiscard]] bool AddCheckedU64(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t* out) noexcept;
[[nodiscard]] bool MulCheckedU64(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t* out) noexcept;

// ---------------------------------------------------------------------------
// Token encoding.
// ---------------------------------------------------------------------------
// A token is safe when it is non-empty, at most 1024 characters, and consists
// only of characters in [A-Za-z0-9_.:@/+*=-]. Anything else is percent-escaped
// byte by byte, so any byte sequence has exactly one canonical spelling.
[[nodiscard]] bool IsSafeToken(std::string_view text) noexcept;
[[nodiscard]] std::string EncodeToken(std::string_view raw);
[[nodiscard]] Expected<std::string> DecodeToken(std::string_view token);

// ---------------------------------------------------------------------------
// Number formatting.
// ---------------------------------------------------------------------------
// Shortest round-trip decimal form of a finite double. Rejects NaN and
// infinities: those are malformed evidence, not values.
[[nodiscard]] Expected<std::string> FormatDouble(double value);
[[nodiscard]] Expected<double> ParseDouble(std::string_view text);

[[nodiscard]] std::string FormatU64(std::uint64_t value);
[[nodiscard]] std::string FormatU32(std::uint32_t value);
[[nodiscard]] std::string FormatU16(std::uint16_t value);
// Maps a field level decoding failure onto the status a whole-artifact parser
// should report. UNSUPPORTED, LIMIT_EXCEEDED and INTEGRITY_FAILURE keep their
// meaning; every other failure means the artifact itself is malformed.
[[nodiscard]] Status NormaliseDecodeStatus(const Status& status);

[[nodiscard]] Expected<std::uint64_t> ParseU64(std::string_view text);
[[nodiscard]] Expected<std::uint32_t> ParseU32(std::string_view text);
[[nodiscard]] Expected<std::uint16_t> ParseU16(std::string_view text);
[[nodiscard]] Expected<bool> ParseBoolToken(std::string_view text);

// ---------------------------------------------------------------------------
// Line assembly and splitting.
// ---------------------------------------------------------------------------
class LineAssembler {
 public:
  LineAssembler() = default;
  explicit LineAssembler(std::string_view record) { Begin(record); }

  void Begin(std::string_view record);
  void Add(std::string_view token);
  void AddU64(std::uint64_t value);
  void AddU32(std::uint32_t value);
  void AddU16(std::uint16_t value);
  void AddDouble(double value);
  void AddKeyU64(std::string_view key, std::uint64_t value);
  void AddKeyDouble(std::string_view key, double value);
  void AddKeyToken(std::string_view key, std::string_view value);
  // Appends key=value without escaping. Used only for values this runtime builds
  // from already-validated fragments, for example a comma separated
  // failure-domain list whose members cannot contain a comma.
  void AddKeyRaw(std::string_view key, std::string_view value);

  [[nodiscard]] const std::string& text() const noexcept { return line_; }
  [[nodiscard]] std::string Take() { return std::move(line_); }

 private:
  std::string line_;
};

// Splits one line into whitespace separated tokens. Rejects empty lines, lines
// longer than kMaxTextLineBytes and tokens longer than 1024 characters.
[[nodiscard]] Expected<std::vector<std::string>> SplitTokens(std::string_view line);

// Finds a trailing key=value field. Returns NotFound when the key is absent and
// MalformedInput for a duplicate key or a field without a separator.
[[nodiscard]] Expected<std::string> FindKeyedField(const std::vector<std::string>& tokens,
                                                   std::size_t first_index, std::string_view key);

// ---------------------------------------------------------------------------
// Binary payload primitives used by the framed transport.
// ---------------------------------------------------------------------------
class ByteWriter {
 public:
  void U8(std::uint8_t value);
  void U16(std::uint16_t value);
  void U32(std::uint32_t value);
  void U64(std::uint64_t value);
  void Bool(bool value);
  void Double(double value);
  void Digest(const Digest256& digest);
  void Incarnation(const IncarnationId& incarnation);
  // length-prefixed byte string
  void Bytes(std::string_view bytes);
  // length-prefixed UTF-8 text
  void Text(std::string_view text);

  [[nodiscard]] const std::string& buffer() const noexcept { return buffer_; }
  [[nodiscard]] std::string Take() { return std::move(buffer_); }

 private:
  std::string buffer_;
};

class ByteReader {
 public:
  explicit ByteReader(std::string_view bytes) : bytes_(bytes) {}

  [[nodiscard]] bool AtEnd() const noexcept { return offset_ == bytes_.size(); }
  [[nodiscard]] std::size_t remaining() const noexcept { return bytes_.size() - offset_; }

  [[nodiscard]] Expected<std::uint8_t> U8();
  [[nodiscard]] Expected<std::uint16_t> U16();
  [[nodiscard]] Expected<std::uint32_t> U32();
  [[nodiscard]] Expected<std::uint64_t> U64();
  [[nodiscard]] Expected<bool> Bool();
  [[nodiscard]] Expected<double> Double();
  [[nodiscard]] Expected<Digest256> Digest();
  [[nodiscard]] Expected<IncarnationId> Incarnation();
  [[nodiscard]] Expected<std::string> Bytes();
  [[nodiscard]] Expected<std::string> Text();

  // Requires that every byte was consumed; rejects trailing garbage.
  [[nodiscard]] Status ExpectEnd() const;

 private:
  [[nodiscard]] Expected<std::string_view> Take(std::size_t count);

  std::string_view bytes_;
  std::size_t offset_ = 0;
};

}  // namespace opp
