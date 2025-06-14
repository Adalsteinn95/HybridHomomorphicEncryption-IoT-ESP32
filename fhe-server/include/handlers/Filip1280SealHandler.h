#ifndef FILIP1280SEALHANDLER_H
#define FILIP1280SEALHANDLER_H

#include "ICipherHandler.h"
#include "Topics.h"
#include "ciphers/filip_1280_seal.h"
#include <seal/seal.h>
#include <memory>
#include <string>
#include <vector>
#include <chrono>

namespace FILIP_1280
{
    class FiLIP_1280_SEAL;
}

class Filip1280SealHandler : public ICipherHandler
{
private:
    std::shared_ptr<seal::SEALContext> context;
    std::shared_ptr<seal::RelinKeys> relin_keys;
    std::shared_ptr<seal::GaloisKeys> galois_keys;
    std::shared_ptr<seal::Evaluator> evaluator;

    const std::string result_topic = FILIP1280_SEAL_RESULT_TOPIC;
    const std::string worker_name = "FILIP1280_SEAL_WORKER";

    void loadContextAndKeys();
    std::vector<uint8_t> getSecretKey();

public:
    Filip1280SealHandler();
    ~Filip1280SealHandler() override = default;

    std::string processMessage(const std::string &payload) override;
    const std::string &getResultTopic() const override;
    const std::string &getWorkerName() const override;
};

#endif // FILIP1280SEALHANDLER_H
