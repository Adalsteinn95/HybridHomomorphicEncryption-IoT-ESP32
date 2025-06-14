#include "ICipherHandler.h"
#include "Topics.h"
#include "filip_1280_helib.h"
#include <helib/helib.h>
#include <memory>
#include <string>
#include <vector>
#include <chrono>

class Filip1280HelibHandler : public ICipherHandler
{
private:
    std::unique_ptr<helib::Context> context_;
    std::unique_ptr<helib::SecKey> secKey_;
    std::unique_ptr<helib::PubKey> pubKey_;
    std::unique_ptr<helib::EncryptedArray> ea_;
    std::unique_ptr<FILIP_1280::FiLIP_1280_HElib> filip1280_helib_impl_;
    const std::string result_topic = FILIP1280_HELIB_RESULT_TOPIC;
    const std::string worker_name = "FILIP1280_HELIB_WORKER";
    void createContextAndKeys();
    std::vector<uint8_t> getSecretKey();

public:
    Filip1280HelibHandler();
    ~Filip1280HelibHandler() override = default;
    std::string processMessage(const std::string &payload) override;
    const std::string &getResultTopic() const override { return result_topic; }
    const std::string &getWorkerName() const override { return worker_name; }
};
