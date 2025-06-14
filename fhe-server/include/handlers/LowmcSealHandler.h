#include "ICipherHandler.h"
#include "Topics.h"
#include <seal/seal.h>
#include <memory>
#include <string>
#include <vector>

namespace LOWMC
{
    class LOWMC_256_128_63_14_SEAL;
}

class LowmcSealHandler : public ICipherHandler
{
private:
    std::shared_ptr<seal::SEALContext> context;
    std::shared_ptr<seal::Evaluator> evaluator;
    std::shared_ptr<seal::RelinKeys> relin_keys;
    std::shared_ptr<seal::GaloisKeys> galois_keys;

    const std::string result_topic = LOWMC_SEAL_RESULT_TOPIC;
    const std::string worker_name = "LOWMC_SEAL_WORKER";

    void loadContextAndKeys();
    std::vector<uint8_t> getSecretKey();

public:
    LowmcSealHandler();
    ~LowmcSealHandler() override = default;

    std::string processMessage(const std::string &payload) override;
    const std::string &getResultTopic() const override;
    const std::string &getWorkerName() const override;
};
