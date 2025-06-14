#include "ICipherHandler.h"
#include "Topics.h"
#include <seal/seal.h>
#include <memory>
#include <string>
#include <vector>

namespace AGRASTA
{
    class AGRASTA_128_SEAL;
}

class AgrastaSealHandler : public ICipherHandler
{
private:
    std::shared_ptr<seal::SEALContext> context;
    std::shared_ptr<seal::RelinKeys> relin_keys;
    std::shared_ptr<seal::GaloisKeys> galois_keys;
    std::shared_ptr<seal::Evaluator> evaluator;

    const std::string result_topic = AGRASTA_SEAL_RESULT_TOPIC;
    const std::string worker_name = "AGRASTA_SEAL_WORKER";

    void loadContextAndKeys();
    std::vector<uint8_t> getSecretKey();

public:
    AgrastaSealHandler();
    ~AgrastaSealHandler() override = default;

    std::string processMessage(const std::string &payload) override;
    const std::string &getResultTopic() const override;
    const std::string &getWorkerName() const override;
};