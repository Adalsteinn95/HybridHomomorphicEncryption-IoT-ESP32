#include "MQTTCallback.h"
#include "Utils.h"  // For get_tid_ss()
#include "Topics.h" // Make sure topics are included
#include <iostream>
#include <chrono>
#include <thread>
#include <exception>
#include <utility> // For std::move
#include <vector>

// Constructor initializes the map from the input vector
MQTTCallback::MQTTCallback(ThreadPool &p,
                           std::vector<std::pair<std::string, std::unique_ptr<ICipherHandler>>> handlers,
                           mqtt::async_client &cli)
    : pool(p), client(cli)
{
    std::cout << "[MQTT Callback] Initializing handler map..." << std::endl;
    for (auto &pair : handlers)
    {
        if (pair.second)
        { // Check if the handler pointer is valid
            // Move the unique_ptr into the map. The map now owns the handler.
            handler_map[pair.first] = std::move(pair.second);
            std::cout << "  - Registered handler for topic: " << pair.first << std::endl;
        }
        else
        {
            std::cerr << "[MQTT Callback Warning] Null handler provided for topic: " << pair.first << std::endl;
        }
    }
    std::cout << "[MQTT Callback] Handler map initialization complete. Size: " << handler_map.size() << std::endl;
}

void MQTTCallback::connected(const std::string &cause)
{
    std::cout << "[MQTT] Connected. Subscribing to compute topics..." << std::endl;
    const int qos = 0; // Default QoS for subscriptions

    if (handler_map.empty())
    {
        std::cerr << "[MQTT Error] No handlers registered. Cannot subscribe." << std::endl;
        return;
    }

    // --- Subscribe to topics one by one ---
    for (const auto &pair : handler_map)
    {
        const std::string &topic_name = pair.first;
        std::cout << "[MQTT] Attempting subscription to: " << topic_name << std::endl;
        try
        {
            // Use the single-topic subscribe overload
            auto suback = client.subscribe(topic_name, qos);

            // Wait for the acknowledgment for this specific subscription
            suback->wait_for(std::chrono::seconds(5)); // Adjust timeout if needed

            // Check the result for this single subscription
            // A return code of 0, 1, or 2 means success (granted QoS level)
            // Other codes might indicate failure or partial success depending on MQTT version/broker.
            // A simple check for >= 0x80 often indicates an MQTTv5 failure.
            // For simplicity here, we check if it's one of the success codes.
            auto rc = suback->get_return_code();            // Paho v3 token interface might return simple int code
            bool success = (rc == 0 || rc == 1 || rc == 2); // Basic success check

            std::cout << "[MQTT] Subscription (" << topic_name << "): "
                      << (success ? "Success" : "Failed")
                      << " (Code: " << rc << ")" << std::endl;
        }
        catch (const mqtt::exception &exc)
        {
            std::cerr << "[MQTT] Exception during subscription to '" << topic_name << "': " << exc.what() << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[MQTT] Standard exception during subscription to '" << topic_name << "': " << e.what() << std::endl;
        }
    }
    std::cout << "[MQTT] All subscription attempts processed." << std::endl;
}

// Find handler in map and dispatch to thread pool
void MQTTCallback::message_arrived(mqtt::const_message_ptr msg)
{
    const auto topic = msg->get_topic();
    const auto payload_str = msg->get_payload_str(); // Assuming string payload for now
    const auto arrival_time = std::chrono::steady_clock::now();
    const auto tid_ss = get_tid_ss();

    std::cout << "[MQTT_CALLBACK TID " << tid_ss.str() << "] Message on topic '" << topic << "'" << std::endl;

    // Lookup handler in the map
    auto it = handler_map.find(topic);
    if (it != handler_map.end())
    {
        active_tasks++;                                 // Increment global counter
        ICipherHandler *handler_ptr = it->second.get(); // Get raw ptr for lambda capture

        // Submit processing task to the thread pool
        pool.submit([this, handler_ptr, payload_str, arrival_time]()
                    {
                        auto tid_ss_worker = get_tid_ss();
                        const std::string &worker_name = handler_ptr->getWorkerName();
                        const std::string &result_topic = handler_ptr->getResultTopic();

                        try
                        {
                            std::cout << "[" << worker_name << " TID " << tid_ss_worker.str() << "] Processing..." << std::endl;

                            // Call the specific handler's processMessage
                            std::string result = handler_ptr->processMessage(payload_str);

                            // Publish the result (async recommended)
                            mqtt::message_ptr pubmsg = mqtt::make_message(result_topic, result);
                            pubmsg->set_qos(1);     // Or other desired QoS
                            client.publish(pubmsg); // Fire-and-forget publish

                            std::cout << "[" << worker_name << " TID " << tid_ss_worker.str()
                                      << "] Completed in "
                                      << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - arrival_time).count()
                                      << "ms. Result published to " << result_topic << std::endl;
                        }
                        catch (const HandlerError &he)
                        {
                            std::cerr << "[" << worker_name << " TID " << tid_ss_worker.str() << " HANDLER ERROR] " << he.what() << std::endl;
                            // Optionally publish to an error topic
                        }
                        catch (const std::exception &e)
                        {
                            std::cerr << "[" << worker_name << " TID " << tid_ss_worker.str() << " UNEXPECTED ERROR] " << e.what() << std::endl;
                            // Optionally publish to an error topic
                        }
                        active_tasks--; // Decrement counter when done
                    });
    }
    else
    {
        std::cerr << "[MQTT_CALLBACK TID " << tid_ss.str() << "] No handler registered for topic: " << topic << "\n";
    }
}