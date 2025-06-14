#ifndef MQTTCALLBACK_H
#define MQTTCALLBACK_H

#include "ThreadPool.h"
#include "ICipherHandler.h"
#include "mqtt/async_client.h"
#include <atomic>
#include <string>
#include <vector>
#include <map>
#include <memory> // For std::unique_ptr

class MQTTCallback : public virtual mqtt::callback,
                     public virtual mqtt::iaction_listener
{
    ThreadPool &pool;
    mqtt::async_client &client;

    // Map from COMPUTE topic string to the handler processing it
    std::map<std::string, std::unique_ptr<ICipherHandler>> handler_map;

    // Single counter for simplicity
    std::atomic<int> active_tasks{0};

    // --- MQTT Methods ---
    void on_failure(const mqtt::token &tok) override {}
    void on_success(const mqtt::token &tok) override {}
    void connected(const std::string &cause) override;
    void connection_lost(const std::string &cause) override
    {
        std::cerr << "[MQTT] Connection lost: " << cause << std::endl;
    }
    void message_arrived(mqtt::const_message_ptr msg) override;
    void delivery_complete(mqtt::delivery_token_ptr token) override {}

public:
    // Constructor accepts a vector of pairs: {compute_topic, handler_unique_ptr}
    MQTTCallback(ThreadPool &p,
                 std::vector<std::pair<std::string, std::unique_ptr<ICipherHandler>>> handlers,
                 mqtt::async_client &cli);

    // Getter for the counter
    int get_active_tasks() const { return active_tasks.load(); }
};

#endif // MQTTCALLBACK_H