#ifndef KREYVIUM13SEALHANDLER_H
#define KREYVIUM13SEALHANDLER_H

#include "ICipherHandler.h" // Base interface
#include "Topics.h"         // MQTT Topic definitions (KREYVIUM13_SEAL_RESULT_TOPIC)
// #include "ciphers/kreyvium_13_seal.h" // Not needed in header if only using pointer/reference via forward declaration
#include <seal/seal.h> // Include SEAL library headers
#include <memory>      // For std::shared_ptr, std::unique_ptr
#include <string>      // For std::string
#include <vector>      // For std::vector

// Forward declaration for the specific implementation class within its namespace
namespace KREYVIUM_13
{
    class KREYVIUM13_SEAL; // Assuming the class name is KREYVIUM13_SEAL in kreyvium_13_seal.h
}

class Kreyvium13SealHandler : public ICipherHandler
{
private:
    // --- SEAL Specific Members (Matching Agrasta's header) ---
    std::shared_ptr<seal::SEALContext> context;
    std::shared_ptr<seal::Evaluator> evaluator;
    std::shared_ptr<seal::RelinKeys> relin_keys;
    std::shared_ptr<seal::GaloisKeys> galois_keys;

    // --- The implementation object is NOT a member, created locally in processMessage ---
    // std::unique_ptr<KREYVIUM_13::KREYVIUM13_SEAL> kreyvium13_seal_impl_; // REMOVED

    // --- Interface Members (Matching Agrasta's header) ---
    const std::string result_topic = KREYVIUM13_SEAL_RESULT_TOPIC; // Specific result topic
    const std::string worker_name = "KREYVIUM13_SEAL_WORKER";      // Specific worker name

    // --- Private Helper Methods (Matching Agrasta's header) ---
    // Renamed from createContext to loadContextAndKeys for consistency
    void loadContextAndKeys();

    // Secret key retrieval helper
    std::vector<uint8_t> getSecretKey();

public:
    /**
     * @brief Constructor: Initializes the SEAL environment and handler members.
     * The specific cipher implementation object is created later in processMessage.
     * @throws std::runtime_error if initialization fails.
     */
    Kreyvium13SealHandler();

    /**
     * @brief Virtual destructor (defaulted), declared override.
     */
    ~Kreyvium13SealHandler() override = default;

    // --- Interface Method Implementations (Declared override) ---

    /**
     * @brief Processes Kreyvium-13 SEAL computation request.
     */
    std::string processMessage(const std::string &payload) override;

    /**
     * @brief Gets the MQTT topic for publishing results.
     */
    const std::string &getResultTopic() const override; // Declared here, defined in .cpp

    /**
     * @brief Gets the descriptive name for logging.
     */
    const std::string &getWorkerName() const override; // Declared here, defined in .cpp
};

#endif // KREYVIUM13SEALHANDLER_H