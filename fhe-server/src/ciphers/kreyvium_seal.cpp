#include "kreyvium_seal.h"

using namespace seal;

namespace KREYVIUM
{

  E_BIT_SEAL &E_BIT_SEAL::operator=(const E_BIT_SEAL &o) noexcept
  {
    this->ct = o.ct;
    this->pt = o.pt;
    this->is_encrypted = o.is_encrypted;
    return *this;
  }

  E_BIT_SEAL &E_BIT_SEAL::operator=(const Ciphertext &o) noexcept
  {
    this->ct = o;
    this->pt = false;
    this->is_encrypted = true;
    return *this;
  }

  E_BIT_SEAL &E_BIT_SEAL::operator=(const bool o) noexcept
  {
    this->pt = o;
    this->is_encrypted = false;
    return *this;
  }

  void E_BIT_SEAL::XOR(const E_BIT_SEAL &b1, const E_BIT_SEAL &b2, E_BIT_SEAL &r,
                       seal::Evaluator &eval)
  {
    if (b1.is_encrypted && b2.is_encrypted)
    {
      r.is_encrypted = true;
      eval.add(b1.ct, b2.ct, r.ct);
      return;
    }

    if (b1.is_encrypted)
    {
      r.is_encrypted = true;
      if (!b2.pt)
      {
        r.ct = b1.ct;
        return;
      }
      Plaintext p;
      p = b2.pt;
      eval.add_plain(b1.ct, p, r.ct);
      return;
    }

    if (b2.is_encrypted)
    {
      r.is_encrypted = true;
      if (!b1.pt)
      {
        r.ct = b2.ct;
        return;
      }
      Plaintext p;
      p = b1.pt;
      eval.add_plain(b2.ct, p, r.ct);
      return;
    }

    r.is_encrypted = false;
    r.pt = b1.pt ^ b2.pt;
  }

  void E_BIT_SEAL::XOR_inplace(E_BIT_SEAL &r, const E_BIT_SEAL &b, seal::Evaluator &eval)
  {
    if (r.is_encrypted && b.is_encrypted)
    {
      eval.add_inplace(r.ct, b.ct);
      return;
    }

    if (r.is_encrypted)
    {
      if (!b.pt)
        return;
      Plaintext p;
      p = b.pt;
      eval.add_plain_inplace(r.ct, p);
      return;
    }

    if (b.is_encrypted)
    {
      r.is_encrypted = true;
      if (!r.pt)
      {
        r.ct = b.ct;
        return;
      }
      Plaintext p;
      p = r.pt;
      eval.add_plain(b.ct, p, r.ct);
      return;
    }

    r.pt = r.pt ^ b.pt;
  }

  void E_BIT_SEAL::XOR_inplace(E_BIT_SEAL &r, const Ciphertext &c, seal::Evaluator &eval)
  {
    if (r.is_encrypted)
    {
      eval.add_inplace(r.ct, c);
      return;
    }

    r.is_encrypted = true;
    if (!r.pt)
    {
      r.ct = c;
      return;
    }
    Plaintext p;
    p = r.pt;
    eval.add_plain(c, p, r.ct);
  }

  void E_BIT_SEAL::XOR_plain_inplace(E_BIT_SEAL &r, const bool &b, seal::Evaluator &eval)
  {
    if (r.is_encrypted)
    {
      if (!b)
      {
        return;
      }
      Plaintext p;
      p = b;
      eval.add_plain_inplace(r.ct, p);
      return;
    }

    r.pt ^= b;
  }

  void E_BIT_SEAL::AND(const E_BIT_SEAL &b1, const E_BIT_SEAL &b2, E_BIT_SEAL &r,
                       seal::Evaluator &eval, seal::RelinKeys &rk)
  {
    if (b1.is_encrypted && b2.is_encrypted)
    {
      r.is_encrypted = true;
      eval.multiply(b1.ct, b2.ct, r.ct);
      eval.relinearize_inplace(r.ct, rk);
      return;
    }

    if (b1.is_encrypted)
    {
      if (b2.pt)
      {
        r.is_encrypted = true;
        r.ct = b1.ct;
        return;
      }
      r.is_encrypted = false;
      r.pt = 0;
      return;
    }

    if (b2.is_encrypted)
    {
      if (b1.pt)
      {
        r.is_encrypted = true;
        r.ct = b2.ct;
        return;
      }
      r.is_encrypted = false;
      r.pt = 0;
      return;
    }

    r.is_encrypted = false;
    r.pt = b1.pt & b2.pt;
  }

  void E_BIT_SEAL::AND_inplace(E_BIT_SEAL &r, const E_BIT_SEAL &b, seal::Evaluator &eval,
                               seal::RelinKeys &rk)
  {
    if (r.is_encrypted && b.is_encrypted)
    {
      eval.multiply_inplace(r.ct, b.ct);
      eval.relinearize_inplace(r.ct, rk);
      return;
    }

    if (r.is_encrypted)
    {
      if (b.pt)
        return;
      r.is_encrypted = false;
      r.pt = 0;
      return;
    }

    if (b.is_encrypted)
    {
      if (r.pt)
      {
        r.is_encrypted = true;
        r.ct = b.ct;
        return;
      }
      r.is_encrypted = false;
      r.pt = false;
      return;
    }

    r.pt = r.pt & b.pt;
  }

  static ivblock convert_iv(const std::vector<uint8_t> &iv)
  {
    ivblock iv_out;
    for (size_t i = 0; i < iv_out.size(); i++)
    {
      iv_out[i] = (iv[i / 8] >> (7 - i % 8)) & 1;
    }
    return iv_out;
  }

  void KREYVIUM_SEAL::encrypt_key()
  {
    secret_key_encrypted.clear();
    secret_key_encrypted.reserve(params.key_size_bits);
    for (size_t i = 0; i < params.key_size_bits; i++)
    {
      int32_t bit = (secret_key[i / 8] >> (7 - i % 8)) & 1;
      Plaintext p;
      p = bit;
      Ciphertext c;
      encryptor.encrypt(p, c);
      secret_key_encrypted.push_back(std::move(c));
    }
  }

  std::vector<Ciphertext> KREYVIUM_SEAL::HE_decrypt(
      std::vector<uint8_t> &ciphertexts, size_t bits)
  {
    std::vector<uint8_t> iv_plain = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                     0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                     0x11, 0x11, 0x11, 0x11};
    ivblock iv = convert_iv(iv_plain);

    std::vector<E_BIT_SEAL> state(STATE_SIZE);
    ivblock inner_iv;
    std::vector<Ciphertext> inner_key(secret_key_encrypted.size());

    std::vector<Ciphertext> out(bits);

    // init
    for (int i = 0; i < 93; i++)
    {
      state[i] = secret_key_encrypted[i];
    }
    for (size_t i = 93; i < 93 + IV_SIZE; i++)
    {
      bool tmp = iv[i - 93];
      state[i] = tmp;
      inner_iv[i - 93] = iv[IV_SIZE + 92 - i];
    }
    for (size_t i = 93 + IV_SIZE; i < STATE_SIZE - 1; i++)
    {
      state[i] = 1;
    }
    state[STATE_SIZE - 1] = 0;
    for (size_t i = 0; i < KREYVIUM_PARAMS.key_size_bits; i++)
    {
      inner_key[i] = secret_key_encrypted[KREYVIUM_PARAMS.key_size_bits - 1 - i];
    }

    std::cout << "initialized..." << std::endl;

    // stream cipher
    size_t warmup = 4 * STATE_SIZE;

    for (size_t i = 0; i < warmup + bits; i++)
    {
      Ciphertext t4 = inner_key[KREYVIUM_PARAMS.key_size_bits - 1];
      bool t5 = inner_iv[IV_SIZE - 1];
      E_BIT_SEAL t1;
      E_BIT_SEAL::XOR(state[65], state[92], t1, evaluator);
      E_BIT_SEAL t2;
      E_BIT_SEAL::XOR(state[161], state[176], t2, evaluator);
      E_BIT_SEAL t3;
      E_BIT_SEAL::XOR(state[242], state[287], t3, evaluator);
      E_BIT_SEAL::XOR_inplace(t3, t4, evaluator);
      if (i >= warmup)
      {
        size_t ind = i - warmup;
        // All ciphers at this point
        evaluator.add(t1.cipher(), t2.cipher(), out[ind]);
        evaluator.add_inplace(out[ind], t3.cipher());

        // add ciphertext
        int32_t bit = (ciphertexts[ind / 8] >> (7 - ind % 8)) & 1;
        if (bit)
        {
          Plaintext p;
          p = bit;
          evaluator.add_plain_inplace(out[ind], p);
        }
      }
      E_BIT_SEAL tmp;
      E_BIT_SEAL::XOR_inplace(t1, state[170], evaluator);
      E_BIT_SEAL::XOR_plain_inplace(t1, t5, evaluator);
      E_BIT_SEAL::AND(state[90], state[91], tmp, evaluator, he_rk);
      E_BIT_SEAL::XOR_inplace(t1, tmp, evaluator);

      E_BIT_SEAL::XOR_inplace(t2, state[263], evaluator);
      E_BIT_SEAL::AND(state[174], state[175], tmp, evaluator, he_rk);
      E_BIT_SEAL::XOR_inplace(t2, tmp, evaluator);

      E_BIT_SEAL::XOR_inplace(t3, state[68], evaluator);
      E_BIT_SEAL::AND(state[285], state[286], tmp, evaluator, he_rk);
      E_BIT_SEAL::XOR_inplace(t3, tmp, evaluator);
      inner_key.pop_back();
      state.pop_back();
      inner_iv <<= 1;
      state.emplace(state.begin(), std::move(t3));
      state[93] = t1;
      state[177] = t2;
      inner_key.emplace(inner_key.begin(), std::move(t4));
      inner_iv[0] = t5;
    }
    return out;
  }

  std::vector<uint8_t> KREYVIUM_SEAL::decrypt_result(
      std::vector<Ciphertext> &ciphertexts)
  {
    size_t size = ceil((double)ciphertexts.size() / 8);
    std::vector<uint8_t> res(size, 0);
    for (size_t i = 0; i < ciphertexts.size(); i++)
    {
      Plaintext p;
      decryptor.decrypt(ciphertexts[i], p);
      uint8_t bit = p[0];
      res[i / 8] |= (bit << (7 - i % 8));
    }
    return res;
  }

} // namespace KREYVIUM
