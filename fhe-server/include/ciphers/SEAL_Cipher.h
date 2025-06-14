#pragma once

#include "Cipher.h"
#include "seal/seal.h"
#include <vector>
#include <memory>
#include <string>
#include <iostream>
#include <sstream>
#include <limits>
#include <algorithm>
#include <stdexcept>
namespace seal
{
    class Ciphertext;
    class PublicKey;
    class SecretKey;
    class RelinKeys;
    class SEALContext;
    class Evaluator;
}

struct SEALParamsInfo
{
    uint64_t poly_modulus_degree;
    uint64_t plain_modulus_value;
    std::string coeff_modulus_info;
    int security_level_value;
};

class SEALCipher
{
public:
    typedef seal::Ciphertext e_bit;
    typedef std::vector<e_bit> e_int;
    typedef std::vector<e_int> e_vector;
    typedef std::vector<e_vector> e_matrix;
    typedef std::vector<uint64_t> vector;
    typedef std::vector<std::vector<uint64_t>> matrix;

    size_t getSecretKeyEncryptedSize() const
    {
        return get_ciphertexts_size_bytes(secret_key_encrypted);
    }

protected:
    std::vector<uint8_t> secret_key;
    BlockCipherParams params;
    uint64_t plain_mod;
    uint64_t mod_degree;

    std::vector<seal::Ciphertext> secret_key_encrypted;

    std::shared_ptr<seal::SEALContext> context;
    seal::KeyGenerator keygen;

    seal::SecretKey he_sk;
    seal::PublicKey he_pk;
    seal::RelinKeys he_rk;

    seal::Encryptor encryptor;
    seal::Evaluator evaluator;
    seal::Decryptor decryptor;

    void CLAinternal(e_int &s, size_t bitsize, size_t levels, size_t size,
                     std::vector<std::vector<e_bit>> &g,
                     std::vector<std::vector<e_bit>> &p, std::vector<e_bit> &c);
    void fpg(const std::vector<e_bit> &g, const std::vector<e_bit> &p, size_t i,
             e_bit &out_g, e_bit &out_p);

public:
    SEALCipher(BlockCipherParams params, std::vector<uint8_t> secret_key,
               std::shared_ptr<seal::SEALContext> con);
    virtual ~SEALCipher() = default;

    size_t get_key_size_bytes() const { return params.key_size_bytes; }
    size_t get_key_size_bits() const { return params.key_size_bits; }
    size_t get_plain_size_bytes() const { return params.plain_size_bytes; }
    size_t get_plain_size_bits() const { return params.plain_size_bits; }
    size_t get_cipher_size_bytes() const { return params.cipher_size_bytes; }
    size_t get_cipher_size_bits() const { return params.cipher_size_bits; }

    /**
     * @brief Gets the serialized size in bytes for a single serializable SEAL object.
     * @tparam T The type of the SEAL object (e.g., Ciphertext, PublicKey, RelinKeys).
     *         T must be a type that has a .save_size() method compatible with SEAL serialization.
     * @param obj The SEAL object.
     * @return The size in bytes, or 0 on error or if object is invalid.
     */
    template <typename T>
    size_t get_seal_object_size_bytes(const T &obj) const;

    /**
     * @brief Gets the total serialized size in bytes for a vector of ciphertexts.
     * @param ciphs The vector of ciphertexts.
     * @return The total size in bytes, or 0 if the vector is empty, contains invalid ciphertexts, or on error.
     */
    size_t get_ciphertexts_size_bytes(const std::vector<seal::Ciphertext> &ciphs) const;

    /**
     * @brief Gets the serialized size in bytes for the SEAL Public Key member (he_pk).
     * @return The size in bytes, or 0 on error or if the key is not set.
     */
    size_t get_public_key_size_bytes() const;

    /**
     * @brief Gets the serialized size in bytes for the SEAL Relinearization Keys member (he_rk).
     * @return The size in bytes, or 0 on error or if the keys are not set.
     */
    size_t get_relinkeys_size_bytes() const;

    /**
     * @brief Retrieves key SEAL context parameters.
     * @return A struct containing parameter information.
     */
    SEALParamsInfo get_context_params_info() const;

    void treeAdd(std::vector<e_int> &tree);

    e_int computeHammingWeight(const std::vector<seal::Ciphertext> &bits);

    void treeAddMul(std::vector<e_int> &tree);

    virtual std::string get_cipher_name() const = 0;

    static std::shared_ptr<seal::SEALContext> create_context(size_t mod_degree,
                                                             uint64_t plain_mod,
                                                             int seclevel = 128);

    void print_parameters();
    int print_noise();

    int print_noise(std::vector<seal::Ciphertext> &ciphs);
    int print_noise(seal::Ciphertext &ciph);

    void halfAdder(e_bit &c_out, e_bit &s, const e_bit &a, const e_bit &b);
    void fullAdder(e_bit &c_out, e_bit &s, const e_bit &a, const e_bit &b,
                   const e_bit &c_in);

    // n-bit
    void rippleCarryAdder(e_int &s, const e_int &a, const e_int &b);
    void carryLookaheadAdder(e_int &s, const e_int &a, const e_int &b,
                             int levels = 2, int size = 4);

    // n x n = n bit multiplier
    void multiply(e_int &s, const e_int &a, const e_int &b);

    // n x n = n bit multiplier
    void multiplyPlain(e_int &s, const e_int &a, const uint64_t b);

    void halfAdderPlain(e_bit &c_out, e_bit &s, const e_bit &a, const bool b);
    void fullAdderPlain(e_bit &c_out, e_bit &s, const e_bit &a, const bool b,
                        const e_bit &c_in);
    void rippleCarryAdderPlain(e_int &s, const e_int &a, const uint64_t b);
    void carryLookaheadAdderPlain(e_int &s, const e_int &a, const uint64_t b,
                                  int levels = 2, int size = 4);

    void encrypt(e_int &out, uint16_t in);
    void encrypt(e_int &out, uint64_t in, size_t bitsize = 64);
    void decrypt(e_int &in, uint16_t &out);
    void decrypt(e_int &in, uint64_t &out);

    void decode(e_vector &out, std::vector<seal::Ciphertext> encoded,
                size_t bitsize);

    // vo = M * vi
    void matMul(e_vector &vo, const matrix &M, const e_vector &vi);

    // vo = vi + b
    void vecAdd(e_vector &vo, const e_vector &vi, const vector &b);

    // vo = M * vi + b
    void affine(e_vector &vo, const matrix &M, const e_vector &vi,
                const vector &b);

    // Pure virtual functions to be implemented by derived classes
    virtual void encrypt_key() = 0;
    virtual std::vector<seal::Ciphertext> HE_decrypt(
        std::vector<uint8_t> &ciphertext, size_t bits) = 0;
    virtual std::vector<uint8_t> decrypt_result(
        std::vector<seal::Ciphertext> &ciphertexts) = 0;
};