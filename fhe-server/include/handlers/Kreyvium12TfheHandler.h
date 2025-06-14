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
#include "ciphers/kreyvium_12_tfhe.h"
#include "Utils.h"

class Kreyvium12TfheHandler : public ICipherHandler
{
private:
    const std::string result_topic = KREYVIUM12_TFHE_COMPUTE_TOPIC;
    const std::string worker_name = "KREYVIUM12_TFHE_WORKER";

    std::unique_ptr<KREYVIUM_12::KREYVIUM12_TFHE> tfhe_impl_ptr;

    size_t get_ciphertexts_size_bytes_tfhe(const TFHECiphertextVec &cts) const;
    TFHEParamsInfo get_tfhe_params_info() const;

public:
    Kreyvium12TfheHandler();

    std::vector<uint8_t> getSecretKey();
    const std::string &getResultTopic() const;
    const std::string &getWorkerName() const;
    std::string processMessage(const std::string &ciphertext_hex_payload);

private:
    void loadContextAndKeys();
};
