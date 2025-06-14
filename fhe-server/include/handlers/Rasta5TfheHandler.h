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
#include "ciphers/rasta_5_tfhe.h"
#include "Utils.h"

class Rasta5TfheHandler : public ICipherHandler
{
private:
    const std::string result_topic = RASTA5_TFHE_RESULT_TOPIC;
    const std::string worker_name = "RASTA5_TFHE_WORKER";

    std::unique_ptr<RASTA_5::RASTA_128_TFHE> tfhe_impl_ptr;

    size_t get_ciphertexts_size_bytes_tfhe(const TFHECiphertextVec &cts) const;
    TFHEParamsInfo get_tfhe_params_info() const;

public:
    Rasta5TfheHandler();

    std::vector<uint8_t> getSecretKey();
    const std::string &getResultTopic() const;
    const std::string &getWorkerName() const;
    std::string processMessage(const std::string &ciphertext_hex_payload);

private:
    void loadContextAndKeys();
};
