#include "opp/spectrum.hpp"

#include <cstdint>

namespace opp {
namespace {

const char* const kHexDigits = "0123456789abcdef";

int HexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

const char* GridKindName(GridKind kind) noexcept {
  switch (kind) {
    case GridKind::Fixed50GHz:
      return "fixed50";
    case GridKind::Flex12_5GHz:
      return "flex12_5";
  }
  return "unknown";
}

bool ParseGridKind(std::string_view text, GridKind* out) noexcept {
  if (out == nullptr) return false;
  if (text == "fixed50") {
    *out = GridKind::Fixed50GHz;
    return true;
  }
  if (text == "flex12_5") {
    *out = GridKind::Flex12_5GHz;
    return true;
  }
  return false;
}

std::uint32_t SlotWidthKhz(GridKind kind) noexcept {
  switch (kind) {
    case GridKind::Fixed50GHz:
      return 50000;
    case GridKind::Flex12_5GHz:
      return 12500;
  }
  return 0;
}

Status SpectrumModel::Validate() const {
  if (slot_count == 0) {
    return Failure(StatusCode::InvalidArgument, "spectrum model must declare at least one slot");
  }
  if (slot_count > kMaxSpectrumSlots) {
    return Failure(StatusCode::LimitExceeded,
                   "spectrum model declares " + std::to_string(static_cast<unsigned>(slot_count)) +
                       " slots, above the supported maximum of " +
                       std::to_string(static_cast<unsigned>(kMaxSpectrumSlots)));
  }
  return OkStatus();
}

std::uint32_t SpectrumModel::ChannelCapacity(std::uint16_t width_slots) const {
  if (width_slots == 0 || width_slots > slot_count) return 0;
  return static_cast<std::uint32_t>(slot_count) - static_cast<std::uint32_t>(width_slots) + 1u;
}

std::optional<std::uint16_t> SlotMask::LowestSetBit() const {
  for (std::size_t word = 0; word < kWords; ++word) {
    if (words_[word] == 0) continue;
    std::uint64_t value = words_[word];
    std::uint16_t bit = 0;
    while ((value & 1ull) == 0) {
      value >>= 1;
      ++bit;
    }
    const std::uint32_t index = static_cast<std::uint32_t>(word) * 64u + bit;
    if (index >= kMaxSpectrumSlots) return std::nullopt;
    return static_cast<std::uint16_t>(index);
  }
  return std::nullopt;
}

SlotMask SlotMask::FirstSlotMask(std::uint16_t width_slots) const {
  SlotMask result;
  if (width_slots == 0 || width_slots > kMaxSpectrumSlots) return result;
  const std::uint32_t last_start = static_cast<std::uint32_t>(kMaxSpectrumSlots) - width_slots;
  for (std::uint32_t start = 0; start <= last_start; ++start) {
    bool available = true;
    for (std::uint32_t offset = 0; offset < width_slots; ++offset) {
      if (!Test(static_cast<std::uint16_t>(start + offset))) {
        available = false;
        break;
      }
    }
    if (available) result.Set(static_cast<std::uint16_t>(start));
  }
  return result;
}

std::string SlotMask::ToHex() const {
  std::string out;
  out.reserve(kWords * 16);
  for (std::size_t index = kWords; index-- > 0;) {
    const std::uint64_t word = words_[index];
    for (int nibble = 15; nibble >= 0; --nibble) {
      out.push_back(kHexDigits[(word >> (nibble * 4)) & 0xfull]);
    }
  }
  return out;
}

Expected<SlotMask> SlotMask::FromHex(std::string_view hex) {
  if (hex.size() != kWords * 16) {
    return Failure(StatusCode::MalformedInput, "slot mask hex must be exactly 64 characters");
  }
  SlotMask mask;
  std::size_t cursor = 0;
  for (std::size_t index = kWords; index-- > 0;) {
    std::uint64_t word = 0;
    for (int nibble = 0; nibble < 16; ++nibble) {
      const int value = HexValue(hex[cursor++]);
      if (value < 0) {
        return Failure(StatusCode::MalformedInput, "slot mask hex contains a non-hex character");
      }
      word = (word << 4) | static_cast<std::uint64_t>(value);
    }
    mask.words_[index] = word;
  }
  return mask;
}

}  // namespace opp
