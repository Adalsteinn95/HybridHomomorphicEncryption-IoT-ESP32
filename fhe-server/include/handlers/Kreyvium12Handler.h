// Kreyvium12Handler.h
#pragma once
#ifndef KREYVIUM12_HANDLER_H
#define KREYVIUM12_HANDLER_H

#include <string>
#include <vector>
#include <memory> // For std::shared_ptr
#include "seal/seal.h" // Include SEAL headers

// Forward declare
namespace KREYVIUM_12 {
    class KREYVIUM12_SEAL;
}

class Kreyvium12Handler {
public:
    Kreyvium12Handler();
    ~Kreyvium12Handler() = default;

    /**
     * @brief Processes an incoming Kreyvium-12 ciphertext (hex encoded).
     *        Performs homomorphic decryption using KREYVIUM12_SEAL.
     * @param ciphertext_str The ciphertext encoded as a hexadecimal string.
     * @return A string containing the result (e.g., "Result: <plaintext_hex>")
     *         or an error message.
     */
    std::string processMessage(const std::string& ciphertext_str);

};

#endif // KREYVIUM12_HANDLER_H