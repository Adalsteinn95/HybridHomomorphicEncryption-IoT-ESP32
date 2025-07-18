#pragma once

#include "kreyvium_12_plain.h" // for KREYVIUM12_PARAMS
#include "SEAL_Cipher.h"

namespace KREYVIUM_12
{

  class E_BIT_12_SEAL
  {
  private:
    seal::Ciphertext ct;
    bool pt;
    bool is_encrypted;

  public:
    E_BIT_12_SEAL() = default;
    E_BIT_12_SEAL(const bool p) : pt(p), is_encrypted(false) {};
    E_BIT_12_SEAL(const seal::Ciphertext &c) : ct(c), is_encrypted(true) {};
    E_BIT_12_SEAL(E_BIT_12_SEAL &&o) noexcept
        : ct(o.ct),
          pt(std::exchange(o.pt, false)),
          is_encrypted(std::exchange(o.is_encrypted, false)) {};
    E_BIT_12_SEAL(const E_BIT_12_SEAL &o) : ct(o.ct), pt(o.pt), is_encrypted(o.is_encrypted) {};
    E_BIT_12_SEAL &operator=(const E_BIT_12_SEAL &o) noexcept;
    E_BIT_12_SEAL &operator=(const seal::Ciphertext &o) noexcept;
    E_BIT_12_SEAL &operator=(const bool o) noexcept;

    const seal::Ciphertext &cipher() const { return ct; };
    const bool &plain() const { return pt; };

    static void XOR(const E_BIT_12_SEAL &b1, const E_BIT_12_SEAL &b2, E_BIT_12_SEAL &r,
                    seal::Evaluator &eval);
    static void XOR_inplace(E_BIT_12_SEAL &r, const E_BIT_12_SEAL &b, seal::Evaluator &eval);
    static void XOR_inplace(E_BIT_12_SEAL &r, const seal::Ciphertext &c,
                            seal::Evaluator &eva);
    static void XOR_plain_inplace(E_BIT_12_SEAL &r, const bool &b, seal::Evaluator &eval);
    static void AND(const E_BIT_12_SEAL &b1, const E_BIT_12_SEAL &b2, E_BIT_12_SEAL &r,
                    seal::Evaluator &eval, seal::RelinKeys &rk);
    static void AND_inplace(E_BIT_12_SEAL &r, const E_BIT_12_SEAL &b, seal::Evaluator &eval,
                            seal::RelinKeys &rk);
  };

  class KREYVIUM12_SEAL : public SEALCipher
  {
  public:
    typedef Kreyvium12 Plain;
    KREYVIUM12_SEAL(std::vector<uint8_t> secret_key,
                    std::shared_ptr<seal::SEALContext> con)
        : SEALCipher(KREYVIUM12_PARAMS, secret_key, con) {}

    virtual ~KREYVIUM12_SEAL() = default;

    virtual std::string get_cipher_name() const
    {
      return "KREYVIUM-12-SEAL (N=46)";
    }
    virtual void encrypt_key();
    virtual std::vector<seal::Ciphertext> HE_decrypt(
        std::vector<uint8_t> &ciphertext, size_t bits);
    virtual std::vector<uint8_t> decrypt_result(
        std::vector<seal::Ciphertext> &ciphertexts);
  };

} // namespace KREYVIUM_12
