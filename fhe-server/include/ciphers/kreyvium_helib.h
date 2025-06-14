#pragma once

#include "kreyvium_plain.h" // for KREYVIUM_PARAMS
#include "HElib_Cipher.h"

namespace KREYVIUM
{

  class E_BIT_Helib
  {
  private:
    helib::Ctxt ct;
    bool pt;
    bool is_encrypted;

  public:
    E_BIT_Helib(helib::PubKey &pk) : ct(pk), pt(false), is_encrypted(false) {};
    E_BIT_Helib(const bool p, helib::PubKey &pk) : ct(pk), pt(p), is_encrypted(false) {};
    E_BIT_Helib(const helib::Ctxt &c) : ct(c), is_encrypted(true) {};
    E_BIT_Helib(E_BIT_Helib &&o) noexcept
        : ct(std::move(o.ct)),
          pt(std::exchange(o.pt, false)),
          is_encrypted(std::exchange(o.is_encrypted, false)) {};
    E_BIT_Helib(const E_BIT_Helib &o) : ct(o.ct), pt(o.pt), is_encrypted(o.is_encrypted) {};
    E_BIT_Helib &operator=(const E_BIT_Helib &o) noexcept;
    E_BIT_Helib &operator=(const helib::Ctxt &o) noexcept;
    E_BIT_Helib &operator=(const bool o) noexcept;

    const helib::Ctxt &cipher() const { return ct; };
    const bool &plain() const { return pt; };

    static void XOR(const E_BIT_Helib &b1, const E_BIT_Helib &b2, E_BIT_Helib &r,
                    const helib::EncryptedArray &ea);
    static void XOR_inplace(E_BIT_Helib &r, const E_BIT_Helib &b,
                            const helib::EncryptedArray &ea);
    static void XOR_inplace(E_BIT_Helib &r, const helib::Ctxt &c,
                            const helib::EncryptedArray &ea);
    static void XOR_plain_inplace(E_BIT_Helib &r, const bool &b,
                                  const helib::EncryptedArray &ea);
    static void AND(const E_BIT_Helib &b1, const E_BIT_Helib &b2, E_BIT_Helib &r);
    static void AND_inplace(E_BIT_Helib &r, const E_BIT_Helib &b);
  };

  class KREYVIUM_HElib : public HElibCipher
  {
  public:
    typedef Kreyvium Plain;
    KREYVIUM_HElib(std::vector<uint8_t> secret_key,
                   std::shared_ptr<helib::Context> con, long L, long c)
        : HElibCipher(KREYVIUM_PARAMS, secret_key, con, L, c) {}

    virtual ~KREYVIUM_HElib() = default;

    virtual std::string get_cipher_name() const { return "KREYVIUM-HElib"; }
    virtual void encrypt_key();
    virtual std::vector<helib::Ctxt> HE_decrypt(std::vector<uint8_t> &ciphertext,
                                                size_t bits);
    virtual std::vector<uint8_t> decrypt_result(
        std::vector<helib::Ctxt> &ciphertexts);
  };

} // namespace KREYVIUM
