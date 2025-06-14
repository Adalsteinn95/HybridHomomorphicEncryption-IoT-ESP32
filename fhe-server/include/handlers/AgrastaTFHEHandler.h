#pragma once

#include <vector>
#include <string>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <limits>
#include <iostream>

#include "tfhe/tfhe.h"
#include "Cipher.h"
#include "TFHE_Cipher.h"
#include "Topics.h"
#include "ICipherHandler.h"
#include "ciphers/agrasta_tfhe.h"
#include "Utils.h"

class AgrastaTFHEHandler : public ICipherHandler
{
private:
    const std::string result_topic = AGRASTA_TFHE_COMPUTE_TOPIC;
    const std::string worker_name = "AGRASTA_TFHE_WORKER";

    std::unique_ptr<AGRASTA::AGRASTA_128_TFHE> tfhe_impl_ptr;

    size_t get_ciphertexts_size_bytes_tfhe(const TFHECiphertextVec &cts) const;
    TFHEParamsInfo get_tfhe_params_info() const;

public:
    AgrastaTFHEHandler();

    std::vector<uint8_t> getSecretKey();
    const std::string &getResultTopic() const;
    const std::string &getWorkerName() const;
    std::string processMessage(const std::string &ciphertext_hex_payload);

private:
    void loadContextAndKeys();
};
