#include "ICipherHandler.h"
#include "Topics.h"
#include "kreyvium_helib.h"
#include <helib/helib.h>
#include <memory>
#include <string>
#include <vector>
#include <chrono>

namespace KREYVIUM
{
    class KREYVIUM_HElib;
}
class KreyviumHelibHandler : public ICipherHandler
{
private:
    std::unique_ptr<helib::Context> context_;
    std::unique_ptr<helib::SecKey> secKey_;
    std::unique_ptr<helib::PubKey> pubKey_;
    std::unique_ptr<helib::EncryptedArray> ea_;
    std::unique_ptr<KREYVIUM::KREYVIUM_HElib> kreyvium_helib_impl_;
    const std::string result_topic = KREYVIUM_HELIB_RESULT_TOPIC;
    const std::string worker_name = "KreyviumHelibHandler";
    void createContextAndKeys();
    std::vector<uint8_t> getSecretKey();

public:
    KreyviumHelibHandler();
    ~KreyviumHelibHandler() override = default;
    std::string processMessage(const std::string &payload) override;
    const std::string &getResultTopic() const override { return result_topic; }
    const std::string &getWorkerName() const override { return worker_name; }
};
