#include "ICipherHandler.h"
#include "Topics.h"
#include "rasta_5_helib.h"
#include <helib/helib.h>
#include <memory>
#include <string>
#include <vector>
#include <chrono>

class Rasta5HelibHandler : public ICipherHandler
{
private:
    std::unique_ptr<helib::Context> context_;
    std::unique_ptr<helib::SecKey> secKey_;
    std::unique_ptr<helib::PubKey> pubKey_;
    std::unique_ptr<helib::EncryptedArray> ea_;
    std::unique_ptr<RASTA_5::RASTA_128_HElib> rasta5_helib_impl_;
    const std::string result_topic = RASTA5_HELIB_RESULT_TOPIC;
    const std::string worker_name = "Rasta5HelibHandler";
    void createContextAndKeys();
    std::vector<uint8_t> getSecretKey();

public:
    Rasta5HelibHandler();
    ~Rasta5HelibHandler() override = default;
    std::string processMessage(const std::string &payload) override;
    const std::string &getResultTopic() const override { return result_topic; }
    const std::string &getWorkerName() const override { return worker_name; }
};
