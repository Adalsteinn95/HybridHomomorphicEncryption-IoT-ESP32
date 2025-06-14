# HybridHomomorphicEncryption-IoT-ESP32

A proof‑of‑concept demonstrating privacy‑preserving data processing in IoT systems using **Hybrid Homomorphic Encryption (HHE)** with FHE‑friendly ciphers on an **ESP32‑based M5Stack Core2** wearable.

## Overview

This project explores the feasibility and performance of integrating **FHE‑friendly symmetric ciphers** on an ESP32 device within a healthcare IoT context. Using **Hybrid Homomorphic Encryption**, the M5Stack Core2 encrypts vital‑sign data locally, while a cloud server homomorphically evaluates the ciphertext—ensuring end‑to‑end privacy for sensitive health data such as heart‑rate and SpO₂ readings.

## Architecture

| Component                               | Responsibilities                                                                                                                                                          |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **M5Stack Core2 (ESP32)**               | • collects heart‑rate/SpO₂ (MAX30100)<br>• Encode & encrypt data with Z₂‑based FHE‑friendly cipher (LowMC, FiLIP, Kreyvium, RASTA/Agrasta)<br>• send ciphertext to server |
| **Cloud Server (Docker Compose stack)** | • Homomorphically evaluate the chosen cipher’s decryption circuit via SEAL (BFV), HElib (BGV) or TFHE<br>• Compute Hamming Weight<br>                                     |

## Getting Started

### Hardware & Software Prerequisites

| Requirement        | Version / Notes                             |
| ------------------ | ------------------------------------------- |
| **ESP32**          | M5Stack Core2 (ESP32‑D0WDQ6‑V3, 8 MB PSRAM) |
| **Sensor**         | MAX30100/MAX30102 heart‑rate / SpO₂ module  |
| **PlatformIO**     | ≥ 6.0 (VS Code extension or CLI)            |
| **Docker**         | 24.x                                        |
| **docker‑compose** | v2 plugin (`docker compose`)                |
| **Python**         | 3.9+ (helper scripts, optional)             |

> **Note:**  
> The required cryptographic and FHE libraries are included as submodules in this repository and will be downloaded to the `thirdparty` directory.  
> If you are cloning this repository for the first time, make sure to initialize and update the submodules:
>
> ```bash
> git submodule update --init --recursive
> ```

### M5Stack Core2 (ESP32 Client)

- The firmware collects sensor data, encrypts it, and sends it to the server.
- **To change the cipher or encryption mode:**  
  Open `client/src/main.cpp` and:
  1. **Change the cipher include:**  
     Replace
     ```cpp
     #include "agrasta.h"
     ```
     with the header for your desired cipher (e.g., `#include "lowmc.h"`).
  2. **Update the cipher object:**  
     Replace
     ```cpp
     AGRASTA_128 *cipher = nullptr;
     ```
     and its instantiation with the correct class for your cipher.
  3. **Update the MQTT topic:**  
     Change the topic in the publish call to match the cipher/FHE backend you enabled on the server, e.g.:
     ```cpp
     const char *topic = "compute/agrasta/seal";
     ```
  4. **Set your Wi-Fi credentials and MQTT broker address:**  
     Edit these lines near the top of `client/src/main.cpp`:
     ```cpp
     const char *ssid = "YOUR_WIFI_SSID";
     const char *password = "YOUR_WIFI_PASSWORD";
     const char *mqtt_server = "BROKER_IP_OR_HOSTNAME";
     const int mqtt_port = 1883;
     ```

### Build & Flash the Firmware

```bash
cd client

# List available environments (defined in platformio.ini)
platformio run --list-targets

# Open a serial monitor
platformio device monitor
```

### How the FHE Server Works

- The FHE server connects to the MQTT broker and listens for encrypted data on specific topics.
- For each supported cipher and FHE library, there is a handler.
- **To enable a cipher/FHE combination:**  
  Uncomment its line in `main.cpp` (see the `handlers.emplace_back(...)` lines).
- Only the uncommented handlers will be active and process incoming requests.
- When a message arrives, the server dispatches it to the correct handler, which processes the ciphertext homomorphically and publishes the result.

### Start the FHE Server

A `docker-compose.yml` is provided in [fhe-server/docker-compose.yml](fhe-server/docker-compose.yml):

To start the server run the following commands.

```bash
cd fhe-server
docker compose up --build
```

## Based On

This work **extends and re‑uses code** from the excellent
[hybrid‑HE‑framework](https://github.com/isec-tugraz/hybrid-HE-framework) (TU Graz).
If you build on this repo, please also cite their original work.

## 📚 References

1. TU Graz **Hybrid HE Framework** – transciphering reference implementation
2. Microsoft SEAL, HElib, TFHE libraries
3. MAXIM MAX30100 Datasheet

## 👤 Author

**Aðalsteinn Ingi Pálsson** — Master’s Thesis, Aarhus University, June 2025  
Supervisor: Diego F. Aranha

> _Privacy‑Preserving Data Processing in IoT Systems using HHE: A study and demonstration using FHE‑friendly ciphers on ESP32_
