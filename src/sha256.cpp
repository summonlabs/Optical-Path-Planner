#include "opp/sha256.hpp"

#include <array>
#include <cstring>

namespace opp {
namespace {

constexpr std::uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

inline std::uint32_t RotateRight(std::uint32_t value, std::uint32_t count) {
  return (value >> count) | (value << (32u - count));
}

}  // namespace

void Sha256::Reset() {
  state_[0] = 0x6a09e667u;
  state_[1] = 0xbb67ae85u;
  state_[2] = 0x3c6ef372u;
  state_[3] = 0xa54ff53au;
  state_[4] = 0x510e527fu;
  state_[5] = 0x9b05688cu;
  state_[6] = 0x1f83d9abu;
  state_[7] = 0x5be0cd19u;
  total_bytes_ = 0;
  buffered_ = 0;
  std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::Compress(const std::uint8_t block[kBlockBytes]) {
  std::uint32_t schedule[64];
  for (std::size_t i = 0; i < 16; ++i) {
    schedule[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
                  (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                  (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                  static_cast<std::uint32_t>(block[i * 4 + 3]);
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 = RotateRight(schedule[i - 15], 7) ^ RotateRight(schedule[i - 15], 18) ^
                             (schedule[i - 15] >> 3);
    const std::uint32_t s1 = RotateRight(schedule[i - 2], 17) ^ RotateRight(schedule[i - 2], 19) ^
                             (schedule[i - 2] >> 10);
    schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
    const std::uint32_t choose = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + choose + kRoundConstants[i] + schedule[i];
    const std::uint32_t s0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
    const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::Update(const void* data, std::size_t size) {
  if (size == 0) return;
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  total_bytes_ += static_cast<std::uint64_t>(size);
  std::size_t offset = 0;
  if (buffered_ > 0) {
    while (buffered_ < kBlockBytes && offset < size) {
      buffer_[buffered_++] = bytes[offset++];
    }
    if (buffered_ == kBlockBytes) {
      Compress(buffer_);
      buffered_ = 0;
    }
  }
  while (size - offset >= kBlockBytes) {
    Compress(bytes + offset);
    offset += kBlockBytes;
  }
  while (offset < size) {
    buffer_[buffered_++] = bytes[offset++];
  }
}

Digest256 Sha256::Finalize() const {
  Sha256 copy = *this;
  const std::uint64_t bit_length = copy.total_bytes_ * 8ull;
  const std::uint8_t padding = 0x80u;
  copy.Update(&padding, 1);
  const std::uint8_t zero = 0x00u;
  while (copy.buffered_ != 56) {
    copy.Update(&zero, 1);
  }
  std::uint8_t length_bytes[8];
  for (std::size_t i = 0; i < 8; ++i) {
    length_bytes[i] = static_cast<std::uint8_t>((bit_length >> (56u - 8u * i)) & 0xffu);
  }
  copy.Update(length_bytes, 8);

  Digest256 digest;
  for (std::size_t i = 0; i < 8; ++i) {
    digest.bytes[i * 4] = static_cast<std::uint8_t>((copy.state_[i] >> 24) & 0xffu);
    digest.bytes[i * 4 + 1] = static_cast<std::uint8_t>((copy.state_[i] >> 16) & 0xffu);
    digest.bytes[i * 4 + 2] = static_cast<std::uint8_t>((copy.state_[i] >> 8) & 0xffu);
    digest.bytes[i * 4 + 3] = static_cast<std::uint8_t>(copy.state_[i] & 0xffu);
  }
  return digest;
}

Digest256 Sha256::Of(const void* data, std::size_t size) {
  Sha256 hasher;
  hasher.Update(data, size);
  return hasher.Finalize();
}

Digest256 Sha256::Of(std::string_view text) { return Of(text.data(), text.size()); }

bool Sha256SelfTest(std::string* detail) {
  struct Vector {
    const char* input;
    const char* expected;
  };
  static const Vector vectors[] = {
      {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
      {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
      {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
       "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
      {"The quick brown fox jumps over the lazy dog",
       "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
      // 112 bytes: one full block plus a partial block, exercising the buffered path.
      {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnop"
       "qrstu",
       "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
  };
  for (const Vector& vector : vectors) {
    const Digest256 digest = Sha256::Of(std::string_view(vector.input));
    const std::string hex = digest.ToHex();
    if (hex != vector.expected) {
      if (detail != nullptr) {
        *detail = "sha256 vector mismatch: got " + hex + " want " + vector.expected;
      }
      return false;
    }
  }

  // Incremental hashing must agree with one-shot hashing, including across block
  // boundaries and for a message split byte by byte.
  std::string message;
  for (int i = 0; i < 1000; ++i) {
    message.push_back(static_cast<char>('a' + (i % 26)));
  }
  const Digest256 one_shot = Sha256::Of(message);
  Sha256 incremental;
  for (std::size_t i = 0; i < message.size(); ++i) {
    incremental.Update(message.data() + i, 1);
  }
  if (incremental.Finalize() != one_shot) {
    if (detail != nullptr) *detail = "sha256 incremental hashing disagrees with one-shot hashing";
    return false;
  }
  if (detail != nullptr) *detail = "sha256 vectors ok";
  return true;
}

}  // namespace opp
