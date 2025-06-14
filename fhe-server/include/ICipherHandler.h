#ifndef ICIPHERHANDLER_H
#define ICIPHERHANDLER_H

#include <string>
#include <stdexcept> // For custom exceptions

// Custom exception for handler errors
class HandlerError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

// Interface for all cipher processing handlers
class ICipherHandler
{
public:
    virtual ~ICipherHandler() = default; // Essential virtual destructor

    /**
     * @brief Processes the incoming MQTT payload (ciphertext, parameters, etc.).
     * @param payload The raw payload string from MQTT.
     * @return A string representing the result (e.g., decrypted plaintext, status).
     * @throws HandlerError If processing fails in a way that should be reported.
     * @throws std::exception For other unexpected errors.
     */
    virtual std::string processMessage(const std::string &payload) = 0;

    /**
     * @brief Returns the MQTT topic used to publish results for this handler.
     */
    virtual const std::string &getResultTopic() const = 0;

    /**
     * @brief Returns a descriptive name for logging purposes.
     */
    virtual const std::string &getWorkerName() const = 0;
};

#endif // ICIPHERHANDLER_H