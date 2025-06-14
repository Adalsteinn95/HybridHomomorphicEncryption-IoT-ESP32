#include "ICipherHandler.h"
#include "Topics.h"
#include "kreyvium_12_helib.h"
#include <helib/helib.h>
#include <memory>
#include <string>
#include <vector>
#include <chrono>

namespace KREYVIUM_12
{
    class KREYVIUM12_HElib;
}
class Kreyvium12HelibHandler : public ICipherHandler
{
private:
    std::unique_ptr<helib::Context> context_;
    std::unique_ptr<helib::SecKey> secKey_;
    std::unique_ptr<helib::PubKey> pubKey_;
    std::unique_ptr<helib::EncryptedArray> ea_;
    std::unique_ptr<KREYVIUM_12::KREYVIUM12_HElib> kreyvium12_helib_impl_;
    const std::string result_topic = KREYVIUM12_HELIB_RESULT_TOPIC;
    const std::string worker_name = "Kreyvium12HelibHandler";
    void createContextAndKeys();
    std::vector<uint8_t> getSecretKey();

public:
    Kreyvium12HelibHandler();
    ~Kreyvium12HelibHandler() override = default;
    std::string processMessage(const std::string &payload) override;
    const std::string &getResultTopic() const override { return result_topic; }
    const std::string &getWorkerName() const override { return worker_name; }
};
