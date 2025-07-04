#pragma once

#include "kreyvium_plain.h" // for KREYVIUM_PARAMS
#include "SEAL_Cipher.h"

namespace KREYVIUM
{

    class E_BIT_SEAL
    {
    private:
        seal::Ciphertext ct;
        bool pt;
        bool is_encrypted;

    public:
        E_BIT_SEAL() = default;
        E_BIT_SEAL(const bool p) : pt(p), is_encrypted(false) {};
        E_BIT_SEAL(const seal::Ciphertext &c) : ct(c), is_encrypted(true) {};
        E_BIT_SEAL(E_BIT_SEAL &&o) noexcept
            : ct(o.ct),
              pt(std::exchange(o.pt, false)),
              is_encrypted(std::exchange(o.is_encrypted, false)) {};
        E_BIT_SEAL(const E_BIT_SEAL &o) : ct(o.ct), pt(o.pt), is_encrypted(o.is_encrypted) {};
        E_BIT_SEAL &operator=(const E_BIT_SEAL &o) noexcept;
        E_BIT_SEAL &operator=(const seal::Ciphertext &o) noexcept;
        E_BIT_SEAL &operator=(const bool o) noexcept;

        const seal::Ciphertext &cipher() const { return ct; };
        const bool &plain() const { return pt; };

        static void XOR(const E_BIT_SEAL &b1, const E_BIT_SEAL &b2, E_BIT_SEAL &r,
                        seal::Evaluator &eval);
        static void XOR_inplace(E_BIT_SEAL &r, const E_BIT_SEAL &b, seal::Evaluator &eval);
        static void XOR_inplace(E_BIT_SEAL &r, const seal::Ciphertext &c,
                                seal::Evaluator &eva);
        static void XOR_plain_inplace(E_BIT_SEAL &r, const bool &b, seal::Evaluator &eval);
        static void AND(const E_BIT_SEAL &b1, const E_BIT_SEAL &b2, E_BIT_SEAL &r,
                        seal::Evaluator &eval, seal::RelinKeys &rk);
        static void AND_inplace(E_BIT_SEAL &r, const E_BIT_SEAL &b, seal::Evaluator &eval,
                                seal::RelinKeys &rk);
    };

    class KREYVIUM_SEAL : public SEALCipher
    {
    public:
        typedef Kreyvium Plain;
        KREYVIUM_SEAL(std::vector<uint8_t> secret_key,
                      std::shared_ptr<seal::SEALContext> con)
            : SEALCipher(KREYVIUM_PARAMS, secret_key, con) {}

        virtual ~KREYVIUM_SEAL() = default;

        virtual std::string get_cipher_name() const { return "KREYVIUM-SEAL"; }
        virtual void encrypt_key();
        virtual std::vector<seal::Ciphertext> HE_decrypt(
            std::vector<uint8_t> &ciphertext, size_t bits);
        virtual std::vector<uint8_t> decrypt_result(
            std::vector<seal::Ciphertext> &ciphertexts);
    };

} // namespace KREYVIUM
