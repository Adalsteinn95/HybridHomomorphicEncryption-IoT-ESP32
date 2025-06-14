#include "ICipherHandler.h"
#include "Topics.h"
#include "lowmc_helib.h"
#include <helib/helib.h>
#include <memory>
#include <string>
#include <vector>
#include <chrono>

class LowmcHelibHandler : public ICipherHandler
{
private:
    std::unique_ptr<helib::Context> context_;
    std::unique_ptr<helib::SecKey> secKey_;
    std::unique_ptr<helib::PubKey> pubKey_;
    std::unique_ptr<helib::EncryptedArray> ea_;
    std::unique_ptr<LOWMC::LOWMC_256_128_63_14_HElib> lowmc_helib_impl_;
    const std::string result_topic = LOWMC_HELIB_RESULT_TOPIC;
    const std::string worker_name = "LOWMC_HELIB_WORKER";
    void createContextAndKeys();
    std::vector<uint8_t> getSecretKey();

public:
    LowmcHelibHandler();
    ~LowmcHelibHandler() override = default;
    std::string processMessage(const std::string &payload) override;
    const std::string &getResultTopic() const override { return result_topic; }
    const std::string &getWorkerName() const override { return worker_name; }
};
