#include "rasta_6_tfhe.h"

#include <iostream>

namespace RASTA_6
{

  void RASTA_128_TFHE::encrypt_key()
  {
    secret_key_encrypted.init(params.key_size_bits, context);
    for (size_t i = 0; i < params.key_size_bits; i++)
    {
      uint8_t bit = (secret_key[i / 8] >> (7 - i % 8)) & 1;
      bootsSymEncrypt(&secret_key_encrypted[i], bit, he_sk);
    }
  }

  TFHECiphertextVec RASTA_128_TFHE::HE_decrypt(std::vector<uint8_t> &ciphertexts,
                                               size_t bits)
  {
    size_t num_block = ceil((double)bits / params.cipher_size_bits);

    Rasta rasta;
    TFHECiphertextVec result(bits, context);

    for (size_t i = 0; i < num_block; i++)
    {
      rasta.genInstance(0, i + 1, false);

      TFHECiphertextVec state = secret_key_encrypted;

      for (unsigned r = 1; r <= rounds; ++r)
      {
        std::cout << "round " << r << std::endl;

        MultiplyWithGF2Matrix(rasta.LinMatrices[r - 1], state);
        addConstant(state, rasta.roundconstants[r - 1]);
        sboxlayer(state);
      }

      std::cout << "final add" << std::endl;

      MultiplyWithGF2Matrix(rasta.LinMatrices[rounds], state);
      addConstant(state, rasta.roundconstants[rounds]);
      add(state, secret_key_encrypted);

      // add cipher
      for (size_t k = 0; k < blocksize && i * blocksize + k < bits; k++)
      {
        size_t ind = i * blocksize + k;
        int32_t bit = (ciphertexts[ind / 8] >> (7 - ind % 8)) & 1;
        if (!bit)
          lweCopy(&result[ind], &state[k], he_pk->params->in_out_params);
        else
          bootsNOT(&result[ind], &state[k], he_pk);
      }
    }

    return result;
  }

  std::vector<uint8_t> RASTA_128_TFHE::decrypt_result(
      TFHECiphertextVec &ciphertexts)
  {
    size_t size = ceil((double)ciphertexts.size() / 8);
    std::vector<uint8_t> res(size, 0);
    for (size_t i = 0; i < ciphertexts.size(); i++)
    {
      uint8_t bit = bootsSymDecrypt(&ciphertexts[i], he_sk) & 0x1;
      res[i / 8] |= (bit << (7 - i % 8));
    }
    return res;
  }

  void RASTA_128_TFHE::MultiplyWithGF2Matrix(const std::vector<block> &matrix,
                                             TFHECiphertextVec &state)
  {
    TFHECiphertextVec out(params.cipher_size_bits, context);
    for (unsigned i = 0; i < params.cipher_size_bits; ++i)
    {
      bool init = false;
      for (unsigned j = 0; j < params.cipher_size_bits; ++j)
      {
        if (!matrix[i][j])
          continue;
        if (!init)
        {
          lweCopy(&out[i], &state[j], he_pk->params->in_out_params);
          init = true;
        }
        else
          bootsXOR(&out[i], &out[i], &state[j], he_pk);
      }
    }
    state = out;
  }

  void RASTA_128_TFHE::addConstant(TFHECiphertextVec &state,
                                   const block &constant)
  {
    for (size_t i = 0; i < params.cipher_size_bits; i++)
    {
      if (!constant[i])
        continue;
      bootsNOT(&state[i], &state[i], he_pk);
    }
  }

  void RASTA_128_TFHE::add(TFHECiphertextVec &state, TFHECiphertextVec &key)
  {
    for (size_t i = 0; i < params.cipher_size_bits; i++)
    {
      bootsXOR(&state[i], &state[i], &key[i], he_pk);
    }
  }

  void RASTA_128_TFHE::sboxlayer(TFHECiphertextVec &state)
  {
    TFHECiphertextVec out(params.cipher_size_bits, context);

    for (size_t i = 0; i < params.cipher_size_bits; i++)
    {
      int i_1 = (i + 1) % params.cipher_size_bits;
      int i_2 = (i + 2) % params.cipher_size_bits;

      bootsNOT(&out[i], &state[i_1], he_pk);
      bootsAND(&out[i], &out[i], &state[i_2], he_pk);
      bootsXOR(&out[i], &out[i], &state[i], he_pk);
    }

    state = out;
  }

} // namespace RASTA_6
