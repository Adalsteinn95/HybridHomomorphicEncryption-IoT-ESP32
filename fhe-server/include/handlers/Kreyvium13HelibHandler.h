#include "ICipherHandler.h"
#include "Topics.h"
#include "kreyvium_13_helib.h"
#include <helib/helib.h>
#include <memory>
#include <string>
#include <vector>
#include <chrono>

namespace KREYVIUM_13
{
    class KREYVIUM13_HElib;
}
class Kreyvium13HelibHandler : public ICipherHandler
{
private:
    std::unique_ptr<helib::Context> context_;
    std::unique_ptr<helib::SecKey> secKey_;
    std::unique_ptr<helib::PubKey> pubKey_;
    std::unique_ptr<helib::EncryptedArray> ea_;
    std::unique_ptr<KREYVIUM_13::KREYVIUM13_HElib> kreyvium13_helib_impl_;
    const std::string result_topic = KREYVIUM13_HELIB_RESULT_TOPIC;
    const std::string worker_name = "Kreyvium13HelibHandler";
    void createContextAndKeys();
    std::vector<uint8_t> getSecretKey();

public:
    Kreyvium13HelibHandler();
    ~Kreyvium13HelibHandler() override = default;
    std::string processMessage(const std::string &payload) override;
    const std::string &getResultTopic() const override { return result_topic; }
    const std::string &getWorkerName() const override { return worker_name; }
};
