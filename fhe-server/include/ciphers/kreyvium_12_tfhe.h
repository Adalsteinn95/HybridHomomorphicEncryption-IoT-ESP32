#pragma once

#include "kreyvium_12_plain.h" // for KREYVIUM12_PARAMS
#include "TFHE_Cipher.h"

namespace KREYVIUM_12
{

  class E_BIT_12_TFHE
  {
  private:
    TFHECiphertext ct;
    bool pt;
    bool is_encrypted;

  public:
    E_BIT_12_TFHE() : pt(false), is_encrypted(false) {};
    E_BIT_12_TFHE(const bool p) : pt(p), is_encrypted(false) {};
    E_BIT_12_TFHE(TFheGateBootstrappingParameterSet *c) : ct(c), is_encrypted(false) {};
    E_BIT_12_TFHE(const TFHECiphertext &c) : ct(c), is_encrypted(true) {};
    E_BIT_12_TFHE(const E_BIT_12_TFHE &o) : ct(o.ct), pt(o.pt), is_encrypted(o.is_encrypted) {};
    E_BIT_12_TFHE(E_BIT_12_TFHE &&o) noexcept
        : ct(std::move(o.ct)),
          pt(std::exchange(o.pt, false)),
          is_encrypted(std::exchange(o.is_encrypted, false)) {};
    E_BIT_12_TFHE &operator=(const E_BIT_12_TFHE &o) noexcept;
    E_BIT_12_TFHE &operator=(const TFHECiphertext &o) noexcept;
    E_BIT_12_TFHE &operator=(LweSample &o) noexcept;
    E_BIT_12_TFHE &operator=(const bool o) noexcept;

    const TFHECiphertext &cipher() const { return ct; };
    const bool &plain() const { return pt; };

    static void XOR(const E_BIT_12_TFHE &b1, const E_BIT_12_TFHE &b2, E_BIT_12_TFHE &r,
                    const TFheGateBootstrappingCloudKeySet *pk);
    static void XOR_inplace(E_BIT_12_TFHE &r, const E_BIT_12_TFHE &b,
                            const TFheGateBootstrappingCloudKeySet *pk);
    static void XOR_inplace(E_BIT_12_TFHE &r, const TFHECiphertext &c,
                            const TFheGateBootstrappingCloudKeySet *pk);
    static void XOR_plain_inplace(E_BIT_12_TFHE &r, const bool &b,
                                  const TFheGateBootstrappingCloudKeySet *pk);
    static void AND(const E_BIT_12_TFHE &b1, const E_BIT_12_TFHE &b2, E_BIT_12_TFHE &r,
                    const TFheGateBootstrappingCloudKeySet *pk);
    static void AND_inplace(E_BIT_12_TFHE &r, const E_BIT_12_TFHE &b,
                            const TFheGateBootstrappingCloudKeySet *pk);
  };

  class KREYVIUM12_TFHE : public TFHECipher
  {
  public:
    typedef Kreyvium12 Plain;
    KREYVIUM12_TFHE(std::vector<uint8_t> secret_key, int seclevel = 128)
        : TFHECipher(KREYVIUM12_PARAMS, secret_key, seclevel) {}

    virtual ~KREYVIUM12_TFHE() = default;

    virtual std::string get_cipher_name() const
    {
      return "KREYVIUM-12-TFHE (N=46)";
    }
    virtual void encrypt_key();
    virtual TFHECiphertextVec HE_decrypt(std::vector<uint8_t> &ciphertext,
                                         size_t bits);
    virtual std::vector<uint8_t> decrypt_result(TFHECiphertextVec &ciphertexts);
  };

} // namespace KREYVIUM_12
