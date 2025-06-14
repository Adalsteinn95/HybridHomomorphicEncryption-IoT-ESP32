#include "ICipherHandler.h"
#include "Topics.h"
#include <seal/seal.h>
#include <memory>
#include <string>
#include <vector>

namespace RASTA_5
{
    class RASTA_128_SEAL;
}

class Rasta5SealHandler : public ICipherHandler
{
private:
    std::shared_ptr<seal::SEALContext> context;
    std::shared_ptr<seal::Evaluator> evaluator;
    std::shared_ptr<seal::RelinKeys> relin_keys;
    std::shared_ptr<seal::GaloisKeys> galois_keys;

    const std::string result_topic = RASTA5_SEAL_RESULT_TOPIC;
    const std::string worker_name = "RASTA5_SEAL_WORKER";

    void loadContextAndKeys();
    std::vector<uint8_t> getSecretKey();

public:
    Rasta5SealHandler();
    ~Rasta5SealHandler() override = default;

    std::string processMessage(const std::string &payload) override;
    const std::string &getResultTopic() const override;
    const std::string &getWorkerName() const override;
};
