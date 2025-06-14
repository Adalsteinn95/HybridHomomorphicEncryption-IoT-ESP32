#include "mqtt/async_client.h"
#include "ThreadPool.h"
#include "MQTTCallback.h"
#include "Topics.h" // Include topic definitions
#include "ICipherHandler.h"

#include "KreyviumSealHandler.h"
#include "KreyviumHelibHandler.h"
#include "KreyviumTfheHandler.h"
#include "Kreyvium12SealHandler.h"
#include "Kreyvium12HelibHandler.h"
#include "Kreyvium12TfheHandler.h"
#include "Kreyvium13SealHandler.h"
#include "Kreyvium13HelibHandler.h"
#include "Kreyvium13TfheHandler.h"
#include "AgrastaSealHandler.h"
#include "AgrastaHelibHandler.h"
#include "AgrastaTFHEHandler.h"
#include "Filip1280SealHandler.h"
#include "Filip1280HelibHandler.h"
#include "Filip1280TfheHandler.h"
#include "LowmcSealHandler.h"
#include "LowmcHelibHandler.h"
#include "LowmcTFHEHandler.h"
#include "Rasta5SealHandler.h"
#include "Rasta5HelibHandler.h"
#include "Rasta5TfheHandler.h"
#include "Rasta6SealHandler.h"
#include "Rasta6HelibHandler.h"
#include "Rasta6TfheHandler.h"

#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <memory>  // For std::unique_ptr, std::make_unique
#include <utility> // For std::pair, std::move

int main(int argc, char *argv[])
{
    const std::string server_address("tcp://mosquitto:1883");
    const std::string client_id("fhe_server_dispatcher"); // Updated ID
    const int n_threads = 8;                              // Adjust as needed

    std::cout << "Initializing MQTT client..." << std::endl;
    mqtt::async_client client(server_address, client_id);

    std::cout << "Initializing ThreadPool with " << n_threads << " threads..." << std::endl;
    ThreadPool pool(n_threads);

    std::cout << "Instantiating Cipher Handlers..." << std::endl;

    std::vector<std::pair<std::string, std::unique_ptr<ICipherHandler>>> handlers;

    // // --- Populate the handlers vector ---

    // uncomment the handlers you want to use

    // handlers.emplace_back(KREYVIUM_SEAL_COMPUTE_TOPIC, std::make_unique<KreyviumSealHandler>());
    handlers.emplace_back(KREYVIUM_HELIB_COMPUTE_TOPIC, std::make_unique<KreyviumHelibHandler>());
    // handlers.emplace_back(KREYVIUM_TFHE_COMPUTE_TOPIC, std::make_unique<KreyviumTfheHandler>());

    // handlers.emplace_back(KREYVIUM12_SEAL_COMPUTE_TOPIC, std::make_unique<Kreyvium12SealHandler>());
    // handlers.emplace_back(KREYVIUM12_TFHE_COMPUTE_TOPIC, std::make_unique<Kreyvium12TfheHandler>());
    // handlers.emplace_back(KREYVIUM12_HELIB_COMPUTE_TOPIC, std::make_unique<Kreyvium12HelibHandler>());

    // handlers.emplace_back(KREYVIUM13_SEAL_COMPUTE_TOPIC, std::make_unique<Kreyvium13SealHandler>());
    // handlers.emplace_back(KREYVIUM13_HELIB_COMPUTE_TOPIC, std::make_unique<Kreyvium13HelibHandler>());
    // handlers.emplace_back(KREYVIUM13_TFHE_COMPUTE_TOPIC, std::make_unique<Kreyvium13TfheHandler>());

    // handlers.emplace_back(AGRASTA_SEAL_COMPUTE_TOPIC, std::make_unique<AgrastaSealHandler>());
    // handlers.emplace_back(AGRASTA_HELIB_COMPUTE_TOPIC, std::make_unique<AgrastaHelibHandler>());
    // handlers.emplace_back(AGRASTA_TFHE_COMPUTE_TOPIC, std::make_unique<AgrastaTFHEHandler>());

    // handlers.emplace_back(FILIP1280_SEAL_COMPUTE_TOPIC, std::make_unique<Filip1280SealHandler>());
    // handlers.emplace_back(FILIP1280_HELIB_COMPUTE_TOPIC, std::make_unique<Filip1280HelibHandler>());
    // handlers.emplace_back(FILIP1280_TFHE_COMPUTE_TOPIC, std::make_unique<Filip1280TfheHandler>());

    // handlers.emplace_back(LOWMC_SEAL_COMPUTE_TOPIC, std::make_unique<LowmcSealHandler>());
    // handlers.emplace_back(LOWMC_HELIB_COMPUTE_TOPIC, std::make_unique<LowmcHelibHandler>());
    // handlers.emplace_back(LOWMC_TFHE_COMPUTE_TOPIC, std::make_unique<LowmcTFHEHandler>());

    // handlers.emplace_back(RASTA5_SEAL_COMPUTE_TOPIC, std::make_unique<Rasta5SealHandler>());
    // handlers.emplace_back(RASTA5_HELIB_COMPUTE_TOPIC, std::make_unique<Rasta5HelibHandler>());
    // handlers.emplace_back(RASTA5_TFHE_COMPUTE_TOPIC, std::make_unique<Rasta5TfheHandler>());

    // handlers.emplace_back(RASTA6_SEAL_COMPUTE_TOPIC, std::make_unique<Rasta6SealHandler>());
    // handlers.emplace_back(RASTA6_HELIB_COMPUTE_TOPIC, std::make_unique<Rasta6HelibHandler>());
    // handlers.emplace_back(RASTA6_TFHE_COMPUTE_TOPIC, std::make_unique<Rasta6TfheHandler>());
    // --- Add ALL other handlers here ---
    std::cout << handlers.size() << " handlers created." << std::endl;

    std::cout << "Initializing MQTT Callback..." << std::endl;
    // Pass the vector of handlers to the callback. Ownership is moved to the callback's map.
    MQTTCallback callback(pool, std::move(handlers), client);
    client.set_callback(callback);

    mqtt::connect_options conn_opts;
    conn_opts.set_keep_alive_interval(120);
    conn_opts.set_clean_session(true);
    conn_opts.set_automatic_reconnect(true);

    try
    {
        std::cout << "Connecting to MQTT broker at " << server_address << "..." << std::endl;
        client.connect(conn_opts)->wait_for(std::chrono::seconds(120));
        std::cout << "MQTT client connection status: " << (client.is_connected() ? "Connected" : "Failed") << std::endl;
        if (!client.is_connected())
        {
            return 1;
        }

        // Keep the application running
        while (true)
        {
            std::this_thread::sleep_for(std::chrono::seconds(120));
            std::cout << "[STATUS] Active Tasks: " << callback.get_active_tasks() << std::endl;
        }
    }
    catch (const mqtt::exception &exc)
    {
        std::cerr << "MQTT Error: " << exc.what() << std::endl;
        return 1;
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}