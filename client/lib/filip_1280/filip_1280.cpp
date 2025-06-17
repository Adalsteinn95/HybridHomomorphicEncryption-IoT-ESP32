#include "filip_1280.h"
#include <cstring>
#include <algorithm>
#include <cmath>

namespace FILIP_1280 {

static state convert_key(const std::vector<uint8_t>& key) {
  // Convert 512-bit key => std::bitset<512>
  state k;
  // Each bit i is in "key[i/8]" at bit position (7 - i%8)
  // e.g. k[0] is the top bit of key[0], etc.
  for (size_t i = 0; i < k.size(); i++) {
    k[i] = (key[i / 8] >> (7 - (i % 8))) & 1;
  }
  return k;
}

// --------------------
// FiLIP_1280 Methods
// --------------------

std::vector<uint8_t> FiLIP_1280::encrypt(std::vector<uint8_t> plaintext, size_t bits) const {
  FiLIP filip(params, convert_key(secret_key));

  // Example IV
  std::array<uint8_t, 16> iv = {0xab, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  // Generate keystream of length `bits`
  std::vector<uint8_t> keystream = filip.keystream(iv, bits);

  // XOR keystream with plaintext
  for (size_t i = 0; i < keystream.size() && i < plaintext.size(); i++) {
    keystream[i] ^= plaintext[i];
  }
  return keystream;
}

std::vector<uint8_t> FiLIP_1280::decrypt(std::vector<uint8_t> ciphertext, size_t bits) const {
  // Decryption is same as encryption for a stream cipher: regenerate same keystream, XOR
  FiLIP filip(params, convert_key(secret_key));

  std::array<uint8_t, 16> iv = {0xab, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  std::vector<uint8_t> keystream = filip.keystream(iv, bits);

  // XOR keystream with ciphertext to recover plaintext
  for (size_t i = 0; i < keystream.size() && i < ciphertext.size(); i++) {
    keystream[i] ^= ciphertext[i];
  }
  return keystream;
}

void FiLIP_1280::prep_one_block() const {
  // Not implemented
}

// --------------------
// FiLIP Core Methods
// --------------------

FiLIP::FiLIP(BlockCipherParams param, state k)
    : params(param), flag(0), key(k)
{
  // Initialize mbedTLS AES context
  mbedtls_aes_init(&aesCtx);

  // We'll fill aes_random later in set_iv(...)
  memset(aes_random, 0, 16);
  memset(aes_ctxt, 0, 16);
}

FiLIP::~FiLIP() {
  // Free mbedTLS context
  mbedtls_aes_free(&aesCtx);
}

void FiLIP::set_iv(std::array<uint8_t, 16>& iv) {
  // Copy IV bytes into aes_random
  // This is the "key" we use for the forward-secure approach
  memcpy(aes_random, iv.data(), 16);
  flag = 0; // reset usage
}

std::vector<uint8_t> FiLIP::keystream(std::array<uint8_t, 16>& iv, size_t bits) {
  // We'll generate `bits` bits => ceil(bits/8) bytes
  size_t bytes = static_cast<size_t>(std::ceil((double)bits / 8));
  std::vector<uint8_t> out(bytes, 0);

  // Initialize IV as our forward-secure "AES key"
  set_iv(iv);

  // We'll shuffle indexes [0..params.key_size_bits-1]
  std::vector<size_t> ind;
  ind.reserve(params.key_size_bits);
  for (size_t i = 0; i < params.key_size_bits; i++)
    ind.push_back(i);

  state_whitened whitening;

  // For each bit needed
  for (size_t i = 0; i < bits; i++) {
    shuffle(ind);             // random permutation of indexes
    set_whitening(whitening); // set random bits in 'whitening'
    // XOR that with the key bits at permuted indices
    for (size_t j = 0; j < NB_VAR; j++) {
      whitening[j] = whitening[j] ^ key[ind[j]];
    }
    bool bitVal = FLIP(whitening);

    // place bitVal in out[i/8] at position (7 - i%8)
    out[i / 8] |= (bitVal << (7 - (i % 8)));
  }
  return out;
}

void FiLIP::shuffle(std::vector<size_t>& ind) {
  // Fisher-Yates with random from aes_forward_secure
  for (size_t i = params.key_size_bits; i > 0; i--) {
    uint32_t rnd = aes_forward_secure();
    rnd = rnd % i;
    if (rnd != i - 1) {
      std::swap(ind[rnd], ind[i - 1]);
    }
  }
}

void FiLIP::set_whitening(state_whitened& whitening) {
  // For NB_VAR=1280 bits, fill from repeated 32-bit random
  uint32_t randomVal = 0;
  for (size_t i = 0; i < NB_VAR; i++) {
    int rem = static_cast<int>(i % 32);
    if (rem == 0) {
      randomVal = aes_forward_secure();
    }
    whitening[i] = (randomVal >> rem) & 1;
  }
}

uint8_t FiLIP::FLIP(state_whitened& s) {
  // Implement your nonlinear filtering function
  // using MF[] array (monomial config)
  uint8_t out = 0;
  size_t nb = 0;

  // Linear monomials
  for (size_t i = 0; i < MF[0]; i++) {
    out ^= s[nb++];
  }

  // Higher degree monomials
  for (size_t i = 1; i < SIZE; i++) {
    for (size_t j = 0; j < MF[i]; j++) {
      // compute AND over (i+1) bits from s
      uint8_t tmp = s[nb++];
      for (size_t k = 1; k < (i + 1); k++) {
        tmp &= s[nb++];
      }
      out ^= tmp;
    }
  }
  return out;
}

// --------------------
// Forward-Secure AES
// --------------------
uint32_t FiLIP::aes_forward_secure() {
  // We interpret aes_random as the AES key (128 bits).
  // Then we encrypt {0}^128 to refresh aes_random,
  // then encrypt {1}^128 to fill aes_ctxt, from which we extract 4 bytes at a time.
  //
  // The code uses 'flag' to read 4 different 32-bit chunks from aes_ctxt.

  if (flag == 0) {
    // 1) Set key from aes_random
    mbedtls_aes_setkey_enc(&aesCtx, aes_random, 128);

    // 2) Encrypt zeroBlock => overwrites aes_random
    uint8_t zeroBlock[16] = {0};
    uint8_t out1[16];
    mbedtls_aes_crypt_ecb(&aesCtx, MBEDTLS_AES_ENCRYPT, zeroBlock, out1);
    memcpy(aes_random, out1, 16);

    // 3) Encrypt onesBlock => store in aes_ctxt
    uint8_t onesBlock[16];
    memset(onesBlock, 0xFF, 16);
    uint8_t out2[16];
    mbedtls_aes_crypt_ecb(&aesCtx, MBEDTLS_AES_ENCRYPT, onesBlock, out2);
    memcpy(aes_ctxt, out2, 16);

    // Now read the first 4 bytes from aes_ctxt as a 32-bit random
    uint32_t randomVal = (aes_ctxt[0]        ) ^
                        (aes_ctxt[1] <<  8) ^
                        (aes_ctxt[2] << 16) ^
                        (aes_ctxt[3] << 24);
    flag = 1;
    return randomVal;
  }
  else {
    // We read the next 4 bytes from aes_ctxt in each subsequent call,
    // then wrap around after 4 calls
    uint8_t* ptr = aes_ctxt;
    size_t offset = flag * 4; // 4, 8, or 12
    uint32_t randomVal = (ptr[offset]        ) ^
                         (ptr[offset+1] <<  8) ^
                         (ptr[offset+2] << 16) ^
                         (ptr[offset+3] << 24);

    flag++;
    if (flag == 4) {
      // After reading 16 bytes, reset to 0 => next call re-encrypts
      flag = 0;
    }
    return randomVal;
  }
}

}  // namespace FILIP_1280
