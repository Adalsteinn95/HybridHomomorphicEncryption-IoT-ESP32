#pragma once

#include "agrasta_plain.h" // for AGRASTA_128_params
#include "HElib_Cipher.h"

namespace AGRASTA
{

  constexpr bool use_m4ri = false;

  class AGRASTA_128_HElib : public HElibCipher
  {
  public:
    typedef AGRASTA_128 Plain;
    AGRASTA_128_HElib(std::vector<uint8_t> secret_key,
                      std::shared_ptr<helib::Context> con, long L, long c)
        : HElibCipher(AGRASTA_128_PARAMS, secret_key, con, L, c) {}

    virtual ~AGRASTA_128_HElib() = default;

    virtual std::string get_cipher_name() const
    {
      return "AGRASTA-HElib (n=129,r=4)";
    }
    virtual void encrypt_key();
    virtual std::vector<helib::Ctxt> HE_decrypt(std::vector<uint8_t> &ciphertext,
                                                size_t bits);
    virtual std::vector<uint8_t> decrypt_result(
        std::vector<helib::Ctxt> &ciphertexts);

  private:
    void MultiplyWithGF2Matrix(const std::vector<block> &matrix,
                               std::vector<helib::Ctxt> &state);
    void addConstant(std::vector<helib::Ctxt> &state, const block &constant);
    void add(std::vector<helib::Ctxt> &state,
             const std::vector<helib::Ctxt> &key);

    void sboxlayer(std::vector<helib::Ctxt> &state);
  };

} // namespace AGRASTA
