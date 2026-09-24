#include "opp/canonical.hpp"

#include <array>
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>

#include "opp/limits.hpp"

namespace opp {
namespace {

constexpr std::size_t kMaxTokenBytes = 1024;

inline bool IsHexDigit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline int HexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

template <class T>
Expected<T> ParseUnsigned(std::string_view text, T maximum, const char* what) {
  if (text.empty()) {
    return Failure(StatusCode::MalformedInput, std::string(what) + " must not be empty");
  }
  for (char c : text) {
    if (c < '0' || c > '9') {
      return Failure(StatusCode::MalformedInput, std::string(what) + " must be an unsigned decimal integer");
    }
  }
  std::uint64_t value = 0;
  const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
  if (result.ec != std::errc() || result.ptr != text.data() + text.size()) {
    return Failure(StatusCode::MalformedInput, std::string(what) + " is out of range");
  }
  if (value > static_cast<std::uint64_t>(maximum)) {
    return Failure(StatusCode::MalformedInput, std::string(what) + " is out of range");
  }
  return static_cast<T>(value);
}

inline void PutBigEndian64(std::string* out, std::uint64_t value) {
  for (int i = 7; i >= 0; --i) {
    out->push_back(static_cast<char>((value >> (i * 8)) & 0xffu));
  }
}

}  // namespace

bool AddCheckedU64(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t* out) noexcept {
  if (out == nullptr) return false;
  if (lhs > std::numeric_limits<std::uint64_t>::max() - rhs) return false;
  *out = lhs + rhs;
  return true;
}

bool MulCheckedU64(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t* out) noexcept {
  if (out == nullptr) return false;
  if (lhs != 0 && rhs > std::numeric_limits<std::uint64_t>::max() / lhs) return false;
  *out = lhs * rhs;
  return true;
}

namespace {

// Characters that may appear literally in a token. The percent sign is
// deliberately excluded so that an escape can never be mistaken for data.
inline bool IsRawTokenCharacter(char c) noexcept {
  const bool alnum = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
  const bool extra = c == '_' || c == '.' || c == ':' || c == '@' || c == '/' || c == '+' || c == '*' || c == '=' ||
                     c == '-';
  return alnum || extra;
}

}  // namespace

bool IsSafeToken(std::string_view text) noexcept {
  if (text.empty() || text.size() > kMaxTokenBytes) return false;
  for (char c : text) {
    if (!IsRawTokenCharacter(c) && c != '%') return false;
  }
  return true;
}

std::string EncodeToken(std::string_view raw) {
  const bool needs_escaping = [&raw]() {
    if (raw.empty() || raw.size() > kMaxTokenBytes) return true;
    for (char c : raw) {
      if (!IsRawTokenCharacter(c)) return true;
    }
    return false;
  }();
  if (!needs_escaping) return std::string(raw);
  static const char* kHex = "0123456789ABCDEF";
  std::string out;
  // Worst case three bytes per input byte.
  out.reserve(raw.size() * 3);
  for (char c : raw) {
    const auto byte = static_cast<unsigned char>(c);
    if (IsRawTokenCharacter(c)) {
      out.push_back(c);
    } else {
      out.push_back('%');
      out.push_back(kHex[(byte >> 4) & 0x0fu]);
      out.push_back(kHex[byte & 0x0fu]);
    }
  }
  if (out.empty()) out = "%";
  return out;
}

Expected<std::string> DecodeToken(std::string_view token) {
  if (token.empty()) {
    return Failure(StatusCode::MalformedInput, "empty token");
  }
  if (token.size() > kMaxTokenBytes * 3) {
    return Failure(StatusCode::MalformedInput, "token exceeds the maximum encoded length");
  }
  // A lone percent sign is the canonical spelling of the empty string; every
  // other escape is a percent sign followed by exactly two hex digits.
  if (token == "%") return std::string();
  std::string out;
  out.reserve(token.size());
  for (std::size_t i = 0; i < token.size(); ++i) {
    if (token[i] != '%') {
      out.push_back(token[i]);
      continue;
    }
    if (i + 2 >= token.size() || !IsHexDigit(token[i + 1]) || !IsHexDigit(token[i + 2])) {
      return Failure(StatusCode::MalformedInput, "truncated percent escape in token");
    }
    out.push_back(static_cast<char>((HexValue(token[i + 1]) << 4) | HexValue(token[i + 2])));
    i += 2;
  }
  return out;
}

Expected<std::string> FormatDouble(double value) {
  if (!std::isfinite(value)) {
    return Failure(StatusCode::InvalidArgument, "non-finite double cannot be encoded canonically");
  }
  std::array<char, 64> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  if (result.ec != std::errc()) {
    return Failure(StatusCode::Internal, "double formatting failed");
  }
  std::string text(buffer.data(), result.ptr);
  if (text == "-0") text = "0";
  return text;
}

Expected<double> ParseDouble(std::string_view text) {
  if (text.empty()) {
    return Failure(StatusCode::MalformedInput, "double must not be empty");
  }
  for (char c : text) {
    if (!((c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+' || c == 'e' || c == 'E')) {
      return Failure(StatusCode::MalformedInput, "double contains characters outside the numeric grammar");
    }
  }
  double value = 0.0;
  const auto result = std::from_chars(text.data(), text.data() + text.size(), value, std::chars_format::general);
  if (result.ec != std::errc() || result.ptr != text.data() + text.size()) {
    return Failure(StatusCode::MalformedInput, "double could not be parsed exactly");
  }
  if (!std::isfinite(value)) {
    return Failure(StatusCode::MalformedInput, "non-finite double is not valid evidence");
  }
  return value;
}

Status NormaliseDecodeStatus(const Status& status) {
  switch (status.code) {
    case StatusCode::Ok:
    case StatusCode::Unsupported:
    case StatusCode::LimitExceeded:
    case StatusCode::IntegrityFailure:
      return status;
    default:
      break;
  }
  return Failure(StatusCode::MalformedInput, std::string(StatusCodeName(status.code)) + ": " + status.detail);
}

std::string FormatU64(std::uint64_t value) { return std::to_string(value); }
std::string FormatU32(std::uint32_t value) { return std::to_string(value); }
std::string FormatU16(std::uint16_t value) { return std::to_string(static_cast<unsigned>(value)); }

Expected<std::uint64_t> ParseU64(std::string_view text) {
  return ParseUnsigned<std::uint64_t>(text, std::numeric_limits<std::uint64_t>::max(), "u64");
}

Expected<std::uint32_t> ParseU32(std::string_view text) {
  return ParseUnsigned<std::uint32_t>(text, std::numeric_limits<std::uint32_t>::max(), "u32");
}

Expected<std::uint16_t> ParseU16(std::string_view text) {
  return ParseUnsigned<std::uint16_t>(text, std::numeric_limits<std::uint16_t>::max(), "u16");
}

Expected<bool> ParseBoolToken(std::string_view text) {
  if (text == "true" || text == "1") return true;
  if (text == "false" || text == "0") return false;
  return Failure(StatusCode::MalformedInput, "boolean token must be true, false, 1 or 0");
}

void LineAssembler::Begin(std::string_view record) {
  line_.assign(record);
}

void LineAssembler::Add(std::string_view token) {
  if (!line_.empty()) line_.push_back(' ');
  line_ += EncodeToken(token);
}

void LineAssembler::AddU64(std::uint64_t value) {
  if (!line_.empty()) line_.push_back(' ');
  line_ += FormatU64(value);
}

void LineAssembler::AddU32(std::uint32_t value) { AddU64(static_cast<std::uint64_t>(value)); }

void LineAssembler::AddU16(std::uint16_t value) { AddU64(static_cast<std::uint64_t>(value)); }

void LineAssembler::AddDouble(double value) {
  const Expected<std::string> text = FormatDouble(value);
  if (!line_.empty()) line_.push_back(' ');
  line_ += text.ok() ? text.value() : std::string("nan");
}

void LineAssembler::AddKeyU64(std::string_view key, std::uint64_t value) {
  if (!line_.empty()) line_.push_back(' ');
  line_.append(key);
  line_.push_back('=');
  line_ += FormatU64(value);
}

void LineAssembler::AddKeyDouble(std::string_view key, double value) {
  const Expected<std::string> text = FormatDouble(value);
  if (!line_.empty()) line_.push_back(' ');
  line_.append(key);
  line_.push_back('=');
  line_ += text.ok() ? text.value() : std::string("nan");
}

void LineAssembler::AddKeyToken(std::string_view key, std::string_view value) {
  if (!line_.empty()) line_.push_back(' ');
  line_.append(key);
  line_.push_back('=');
  line_ += EncodeToken(value);
}

void LineAssembler::AddKeyRaw(std::string_view key, std::string_view value) {
  if (!line_.empty()) line_.push_back(' ');
  line_.append(key);
  line_.push_back('=');
  line_.append(value);
}

Expected<std::vector<std::string>> SplitTokens(std::string_view line) {
  if (line.empty()) {
    return Failure(StatusCode::MalformedInput, "empty line");
  }
  if (line.size() > kMaxTextLineBytes) {
    return Failure(StatusCode::LimitExceeded, "line exceeds the maximum text line length");
  }
  std::vector<std::string> tokens;
  std::size_t index = 0;
  while (index < line.size()) {
    while (index < line.size() && (line[index] == ' ' || line[index] == '\t')) ++index;
    if (index >= line.size()) break;
    const std::size_t start = index;
    while (index < line.size() && line[index] != ' ' && line[index] != '\t') ++index;
    const std::string_view token = line.substr(start, index - start);
    if (token.size() > kMaxTokenBytes) {
      return Failure(StatusCode::LimitExceeded, "token exceeds the maximum token length");
    }
    tokens.emplace_back(token);
  }
  if (tokens.empty()) {
    return Failure(StatusCode::MalformedInput, "line contains no tokens");
  }
  return tokens;
}

Expected<std::string> FindKeyedField(const std::vector<std::string>& tokens, std::size_t first_index,
                                     std::string_view key) {
  std::string result;
  bool found = false;
  for (std::size_t i = first_index; i < tokens.size(); ++i) {
    const std::string& token = tokens[i];
    if (token.size() <= key.size()) continue;
    if (token.compare(0, key.size(), key) != 0) continue;
    if (token[key.size()] != '=') continue;
    if (found) {
      return Failure(StatusCode::MalformedInput, "duplicate field '" + std::string(key) + "'");
    }
    found = true;
    result = token.substr(key.size() + 1);
  }
  if (!found) {
    return Failure(StatusCode::NotFound, "missing field '" + std::string(key) + "'");
  }
  return result;
}

void ByteWriter::U8(std::uint8_t value) { buffer_.push_back(static_cast<char>(value)); }

void ByteWriter::U16(std::uint16_t value) {
  U8(static_cast<std::uint8_t>(value & 0xffu));
  U8(static_cast<std::uint8_t>((value >> 8) & 0xffu));
}

void ByteWriter::U32(std::uint32_t value) {
  for (int i = 0; i < 4; ++i) U8(static_cast<std::uint8_t>((value >> (i * 8)) & 0xffu));
}

void ByteWriter::U64(std::uint64_t value) {
  for (int i = 0; i < 8; ++i) U8(static_cast<std::uint8_t>((value >> (i * 8)) & 0xffu));
}

void ByteWriter::Bool(bool value) { U8(value ? 1u : 0u); }

void ByteWriter::Double(double value) {
  std::uint64_t bits = 0;
  static_assert(sizeof(bits) == sizeof(value), "double must be 64 bits");
  std::memcpy(&bits, &value, sizeof(bits));
  PutBigEndian64(&buffer_, bits);
}

void ByteWriter::Bytes(std::string_view bytes) {
  U32(static_cast<std::uint32_t>(bytes.size()));
  buffer_.append(bytes);
}

void ByteWriter::Text(std::string_view text) { Bytes(text); }

void ByteWriter::Digest(const Digest256& digest) {
  buffer_.append(reinterpret_cast<const char*>(digest.bytes.data()), digest.bytes.size());
}

void ByteWriter::Incarnation(const IncarnationId& incarnation) {
  buffer_.append(reinterpret_cast<const char*>(incarnation.bytes.data()), incarnation.bytes.size());
}

Expected<std::string_view> ByteReader::Take(std::size_t count) {
  if (count > remaining()) {
    return Failure(StatusCode::MalformedInput, "payload is truncated");
  }
  const std::string_view slice = bytes_.substr(offset_, count);
  offset_ += count;
  return slice;
}

Expected<std::uint8_t> ByteReader::U8() {
  const auto slice = Take(1);
  if (!slice.ok()) return slice.status();
  return static_cast<std::uint8_t>(static_cast<unsigned char>(slice.value()[0]));
}

Expected<std::uint16_t> ByteReader::U16() {
  const auto slice = Take(2);
  if (!slice.ok()) return slice.status();
  const auto* data = reinterpret_cast<const unsigned char*>(slice.value().data());
  return static_cast<std::uint16_t>(data[0] | (static_cast<std::uint16_t>(data[1]) << 8));
}

Expected<std::uint32_t> ByteReader::U32() {
  const auto slice = Take(4);
  if (!slice.ok()) return slice.status();
  const auto* data = reinterpret_cast<const unsigned char*>(slice.value().data());
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) value |= static_cast<std::uint32_t>(data[i]) << (i * 8);
  return value;
}

Expected<std::uint64_t> ByteReader::U64() {
  const auto slice = Take(8);
  if (!slice.ok()) return slice.status();
  const auto* data = reinterpret_cast<const unsigned char*>(slice.value().data());
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) value |= static_cast<std::uint64_t>(data[i]) << (i * 8);
  return value;
}

Expected<bool> ByteReader::Bool() {
  const auto value = U8();
  if (!value.ok()) return value.status();
  if (value.value() > 1u) {
    return Failure(StatusCode::MalformedInput, "boolean byte must be 0 or 1");
  }
  return value.value() == 1u;
}

Expected<double> ByteReader::Double() {
  const auto slice = Take(8);
  if (!slice.ok()) return slice.status();
  const auto* data = reinterpret_cast<const unsigned char*>(slice.value().data());
  std::uint64_t bits = 0;
  for (int i = 0; i < 8; ++i) bits = (bits << 8) | static_cast<std::uint64_t>(data[i]);
  double value = 0.0;
  std::memcpy(&value, &bits, sizeof(value));
  if (!std::isfinite(value)) {
    return Failure(StatusCode::MalformedInput, "transferred double is not finite");
  }
  return value;
}

Expected<std::string> ByteReader::Bytes() {
  const auto length = U32();
  if (!length.ok()) return length.status();
  const auto slice = Take(static_cast<std::size_t>(length.value()));
  if (!slice.ok()) return slice.status();
  return std::string(slice.value());
}

Expected<std::string> ByteReader::Text() { return Bytes(); }

Expected<Digest256> ByteReader::Digest() {
  const auto slice = Take(32);
  if (!slice.ok()) return slice.status();
  Digest256 digest;
  std::memcpy(digest.bytes.data(), slice.value().data(), digest.bytes.size());
  return digest;
}

Expected<IncarnationId> ByteReader::Incarnation() {
  const auto slice = Take(16);
  if (!slice.ok()) return slice.status();
  IncarnationId incarnation;
  std::memcpy(incarnation.bytes.data(), slice.value().data(), incarnation.bytes.size());
  return incarnation;
}

Status ByteReader::ExpectEnd() const {
  if (!AtEnd()) {
    return Failure(StatusCode::MalformedInput, "payload has trailing bytes");
  }
  return OkStatus();
}

}  // namespace opp
