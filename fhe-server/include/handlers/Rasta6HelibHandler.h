#include "ICipherHandler.h"
#include "Topics.h"
#include "rasta_6_helib.h"
#include <helib/helib.h>
#include <memory>
#include <string>
#include <vector>
#include <chrono>

class Rasta6HelibHandler : public ICipherHandler
{
private:
    std::unique_ptr<helib::Context> context_;
    std::unique_ptr<helib::SecKey> secKey_;
    std::unique_ptr<helib::PubKey> pubKey_;
    std::unique_ptr<helib::EncryptedArray> ea_;
    std::unique_ptr<RASTA_6::RASTA_128_HElib> rasta6_helib_impl_;
    const std::string result_topic = RASTA6_HELIB_RESULT_TOPIC;
    const std::string worker_name = "Rasta6HelibHandler";
    void createContextAndKeys();
    std::vector<uint8_t> getSecretKey();

public:
    Rasta6HelibHandler();
    ~Rasta6HelibHandler() override = default;
    std::string processMessage(const std::string &payload) override;
    const std::string &getResultTopic() const override { return result_topic; }
    const std::string &getWorkerName() const override { return worker_name; }
};
