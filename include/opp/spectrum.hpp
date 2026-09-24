#pragma once

// Vendor-neutral spectrum model.
//
// The model is a grid of equally wide slots over an unbounded frequency axis
// with a bounded slot count. A channel is a contiguous run of slots addressed by
// its first slot and its width in slots. Nothing here asserts a physical
// frequency plan: centre frequencies are a property of the evidence supply, and
// this runtime only tracks slot indices.

#include <array>
#include <bit>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "opp/limits.hpp"
#include "opp/status.hpp"

namespace opp {

enum class GridKind : std::uint8_t {
  // Fixed 50 GHz grid; every channel is exactly one slot wide.
  Fixed50GHz = 0,
  // Flexible 12.5 GHz grid; channels span one or more slots.
  Flex12_5GHz = 1,
};

const char* GridKindName(GridKind kind) noexcept;
[[nodiscard]] bool ParseGridKind(std::string_view text, GridKind* out) noexcept;

// Width of one slot in kHz for the given grid. Reported for inspection; the
// planner itself only handles slot indices.
[[nodiscard]] std::uint32_t SlotWidthKhz(GridKind kind) noexcept;

struct SpectrumModel {
  GridKind grid = GridKind::Fixed50GHz;
  std::uint16_t slot_count = 96;

  friend bool operator==(const SpectrumModel&, const SpectrumModel&) = default;
  friend auto operator<=>(const SpectrumModel&, const SpectrumModel&) = default;

  // Validates slot_count against kMaxSpectrumSlots and the grid's minimum.
  [[nodiscard]] Status Validate() const;

  // Number of contiguous slot runs of the given width.
  [[nodiscard]] std::uint32_t ChannelCapacity(std::uint16_t width_slots) const;
};

// A fixed-capacity bit set over spectrum slots. Bits at or above the model's
// slot count are never set by this runtime.
class SlotMask {
 public:
  static constexpr std::size_t kWords = (kMaxSpectrumSlots + 63u) / 64u;

  SlotMask() = default;

  static SlotMask None() { return SlotMask{}; }

  static SlotMask All(std::uint16_t slot_count) {
    SlotMask mask;
    for (std::uint16_t i = 0; i < slot_count && i < kMaxSpectrumSlots; ++i) {
      mask.Set(i);
    }
    return mask;
  }

  void Set(std::uint16_t index) {
    if (index >= kMaxSpectrumSlots) return;
    words_[index / 64u] |= (1ull << (index % 64u));
  }

  void Reset(std::uint16_t index) {
    if (index >= kMaxSpectrumSlots) return;
    words_[index / 64u] &= ~(1ull << (index % 64u));
  }

  [[nodiscard]] bool Test(std::uint16_t index) const {
    if (index >= kMaxSpectrumSlots) return false;
    return (words_[index / 64u] & (1ull << (index % 64u))) != 0;
  }

  void AndWith(const SlotMask& other) {
    for (std::size_t i = 0; i < kWords; ++i) words_[i] &= other.words_[i];
  }

  [[nodiscard]] SlotMask Intersect(const SlotMask& other) const {
    SlotMask result = *this;
    result.AndWith(other);
    return result;
  }

  [[nodiscard]] bool IsEmpty() const {
    for (std::size_t i = 0; i < kWords; ++i) {
      if (words_[i] != 0) return false;
    }
    return true;
  }

  [[nodiscard]] std::uint32_t Count() const {
    std::uint32_t total = 0;
    for (std::size_t i = 0; i < kWords; ++i) total += static_cast<std::uint32_t>(std::popcount(words_[i]));
    return total;
  }

  // Lowest set slot index, or nullopt when empty. This is the deterministic
  // channel selection rule: the lowest-indexed admissible slot wins.
  [[nodiscard]] std::optional<std::uint16_t> LowestSetBit() const;

  // True when every bit set in *this is also set in other.
  [[nodiscard]] bool IsSubsetOf(const SlotMask& other) const {
    for (std::size_t i = 0; i < kWords; ++i) {
      if ((words_[i] & ~other.words_[i]) != 0) return false;
    }
    return true;
  }

  // Derives the set of starting slots for which a run of width_slots contiguous
  // slots is entirely available in this mask.
  [[nodiscard]] SlotMask FirstSlotMask(std::uint16_t width_slots) const;

  friend bool operator==(const SlotMask&, const SlotMask&) = default;
  friend auto operator<=>(const SlotMask&, const SlotMask&) = default;

  [[nodiscard]] const std::array<std::uint64_t, kWords>& words() const noexcept { return words_; }

  // 64 lowercase hex characters, fixed width, most significant word first.
  [[nodiscard]] std::string ToHex() const;
  static Expected<SlotMask> FromHex(std::string_view hex);

 private:
  std::array<std::uint64_t, kWords> words_{};
};

struct Channel {
  std::uint16_t first_slot = 0;
  std::uint16_t width_slots = 1;

  friend bool operator==(const Channel&, const Channel&) = default;
  friend auto operator<=>(const Channel&, const Channel&) = default;
};

}  // namespace opp
