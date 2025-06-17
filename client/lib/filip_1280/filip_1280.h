#pragma once

#include <array>
#include <bitset>
#include <string>
#include <vector>
#include "mbedtls/aes.h"  // Use mbedtls for AES on ESP32

#include "Cipher.h"

namespace FILIP_1280 {

// Blockcipher just for testing a plaintext/ciphertext with specific size
constexpr BlockCipherParams FILIP_1280_PARAMS = {512, 4096, 8, 64, 8, 64};

class FiLIP_1280 : public BlockCipher {
 public:
  // Pass the 512-bit key as a 64-byte vector
  FiLIP_1280(std::vector<uint8_t> secret_key)
      : BlockCipher(FILIP_1280_PARAMS, secret_key) {}

  virtual ~FiLIP_1280() = default;

  virtual std::string get_cipher_name() const { return "FiLIP_1280 (mbedTLS)"; }

  // Encrypt/Decrypt: Generate keystream, XOR with plaintext/ciphertext
  virtual std::vector<uint8_t> encrypt(std::vector<uint8_t> plaintext,
                                       size_t bits) const;
  virtual std::vector<uint8_t> decrypt(std::vector<uint8_t> ciphertext,
                                       size_t bits) const;

  // Not used in this example, but required by the base class
  virtual void prep_one_block() const;
};

constexpr size_t SIZE = 16;
constexpr size_t MF[SIZE] = {
    128, 64, 0, 0, 0, 0, 0, 0,
    0,   0,  0, 0, 0, 0, 0, 64
};  // Monomial filter info for FLIP
constexpr size_t NB_VAR = 1280;

typedef std::bitset<FILIP_1280_PARAMS.key_size_bits> state;  // 512-bit key bits
typedef std::bitset<NB_VAR> state_whitened;

//------------------------------------------------------------------------
// FiLIP CORE
//------------------------------------------------------------------------
class FiLIP {
 private:
  BlockCipherParams params;
  uint8_t flag;                // Tracks how many 32-bit words have been used
  mbedtls_aes_context aesCtx;  // mbedTLS AES context
  uint8_t aes_random[16];      // "Forward-secure" AES key bytes
  uint8_t aes_ctxt[16];        // Last ciphertext block from AES

  // Generates a new 32-bit random from the forward-secure approach:
  // - If flag=0, re-key from aes_random, encrypt zero/ones blocks,
  //   store in aes_random/aes_ctxt.
  // - Otherwise read next 4 bytes from aes_ctxt, up to 4 times total.
  uint32_t aes_forward_secure();

  // If you decide to do a CTR approach later, you can implement this
  void ctr(std::array<uint8_t, 16>& iv, uint64_t counter);

 public:
  // The 512-bit FiLIP key in bit form
  state key;

  FiLIP(BlockCipherParams param, state k = 0);
  ~FiLIP();  // Destructor frees the mbedTLS AES context

  // Sets the IV by copying into aes_random
  void set_iv(std::array<uint8_t, 16>& iv);

  // Overwrites 'whitening' with random bits from aes_forward_secure()
  void set_whitening(state_whitened& whitening);

  // Shuffle an index array using Fisher-Yates with random from aes_forward_secure()
  void shuffle(std::vector<size_t>& ind);

  // Nonlinear filtering function (monomial-based)
  uint8_t FLIP(state_whitened& state);

  // Produce 'bits' bits of keystream by shuffling indexes,
  // mixing them with 'key', and calling FLIP()
  std::vector<uint8_t> keystream(std::array<uint8_t, 16>& iv, size_t bits);
};

}  // namespace FILIP_1280
