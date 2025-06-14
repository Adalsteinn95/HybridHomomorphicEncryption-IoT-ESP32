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
#include "ciphers/filip_1280_tfhe.h"
#include "Utils.h"

class Filip1280TfheHandler : public ICipherHandler
{
private:
    const std::string result_topic = FILIP1280_TFHE_COMPUTE_TOPIC;
    const std::string worker_name = "FILIP1280_TFHE_WORKER";

    std::unique_ptr<FILIP_1280::FiLIP_1280_TFHE> tfhe_impl_ptr;

    size_t get_ciphertexts_size_bytes_tfhe(const TFHECiphertextVec &cts) const;
    TFHEParamsInfo get_tfhe_params_info() const;

public:
    Filip1280TfheHandler();

    std::vector<uint8_t> getSecretKey();
    const std::string &getResultTopic() const;
    const std::string &getWorkerName() const;
    std::string processMessage(const std::string &ciphertext_hex_payload);

private:
    void loadContextAndKeys();
};
