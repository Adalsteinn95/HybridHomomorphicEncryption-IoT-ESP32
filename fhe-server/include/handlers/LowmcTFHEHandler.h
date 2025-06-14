#pragma once

#include <vector>
#include <string>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <limits>
#include <iostream>
#include <iomanip>
#include "ICipherHandler.h"
#include "tfhe/tfhe.h"
#include "Cipher.h"
#include "TFHE_Cipher.h"
#include "ciphers/lowmc_tfhe.h"
#include "Utils.h"

class LowmcTFHEHandler : public ICipherHandler
{
private:
    std::string worker_name;
    std::string result_topic;
    std::unique_ptr<LOWMC::LOWMC_256_128_63_14_TFHE> tfhe_impl_ptr;
    size_t get_ciphertexts_size_bytes_tfhe(const TFHECiphertextVec &cts) const;
    void loadContextAndKeys();

public:
    LowmcTFHEHandler();
    std::vector<uint8_t> getSecretKey();
    const std::string &getResultTopic() const;
    const std::string &getWorkerName() const;
    std::string processMessage(const std::string &ciphertext_hex_payload);
};
