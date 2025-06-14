#include "handlers/Kreyvium13TfheHandler.h"
#include "ciphers/kreyvium_13_tfhe.h"
#include "Utils.h"
#include "ciphers/TFHE_Cipher.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <limits>
#include <memory>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <string>
#include <utility>
#include <map>

#include <tfhe/lwesamples.h>
#include <tfhe/tfhe.h>

const std::string &Kreyvium13TfheHandler::getResultTopic() const { return result_topic; }
const std::string &Kreyvium13TfheHandler::getWorkerName() const { return worker_name; }

std::vector<uint8_t> Kreyvium13TfheHandler::getSecretKey()
{
    std::cout << "[" << worker_name << "] Getting Secret Key..." << std::endl;
    std::vector<uint8_t> key = {
        0x0c, 0x7c, 0xc2, 0x27, 0xec, 0xed, 0x1e, 0x4f,
        0x33, 0xdb, 0xe4, 0xab, 0xdd, 0xfb, 0xb3, 0xbd};
    return key;
}

Kreyvium13TfheHandler::Kreyvium13TfheHandler()
{
    std::cout << "[Handler Init] Initializing " << worker_name << "..." << std::endl;
    try
    {
        loadContextAndKeys();
        std::cout << "[" << worker_name << "] Initialization complete." << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "[" << worker_name << " Init ERROR] Failed to initialize: " << e.what() << std::endl;
        tfhe_impl_ptr = nullptr;
        throw std::runtime_error(worker_name + " Initialization failed: " + std::string(e.what()));
    }
}

void Kreyvium13TfheHandler::loadContextAndKeys()
{
    std::cout << "[" << worker_name << "] Initializing Kreyvium13_TFHE implementation..." << std::endl;
    std::vector<uint8_t> secret_key = getSecretKey();
    int security_level = 128;

    try
    {
        tfhe_impl_ptr = std::make_unique<KREYVIUM_13::KREYVIUM13_TFHE>(secret_key, security_level);
    }
    catch (const std::exception &e)
    {
        tfhe_impl_ptr.reset();
        throw std::runtime_error(worker_name + " Kreyvium13_TFHE construction/TFHE setup failed: " + std::string(e.what()));
    }

    std::cout << "[" << worker_name << "] Kreyvium13_TFHE instance created and TFHE context/keys loaded." << std::endl;
}

std::string Kreyvium13TfheHandler::processMessage(const std::string &ciphertext_hex_payload)
{
    std::chrono::milliseconds keyEncryptTime{0}, heDecryptTime{0},
        heSumTime{0},
        finalDecryptTime{0}, sumDecryptTime{0},
        totalProcessTime{0};
    size_t inputCiphertextSizeBytes = 0;
    size_t encryptedKeySizeBytes = 0;
    size_t heCiphertextSizeBytes = 0;
    size_t heSumResultSizeBytes = 0;
    size_t finalPlaintextSizeBytes = 0;
    size_t heCiphertextCount = 0;
    size_t heSumResultCtCount = 0;
    int noiseBudgetKeyEncrypted = std::numeric_limits<int>::min();
    int noiseBudgetAfterHEDecrypt = std::numeric_limits<int>::min();
    int noiseBudgetAfterSum = std::numeric_limits<int>::min();
    std::string correctness_status = "UNKNOWN";
    std::string final_result_hex = "";
    uint64_t decrypted_sum_value = -1;
    uint64_t ground_truth_sum_value = -1;
    bool hamming_weight_match = false;
    uint64_t actual_polyModDegree = 0;
    uint64_t actual_plainModulusVal = 0;
    std::string actual_coeffModulusInfo = "N/A";
    int actual_securityLevelVal = 128;

    auto total_start_time = std::chrono::high_resolution_clock::now();

    try
    {

        std::cout << "\n[" << worker_name << "] --- Starting processMessage ---" << std::endl;

        std::vector<uint8_t> cipher_bytes = hexStringToBytes(ciphertext_hex_payload);
        inputCiphertextSizeBytes = cipher_bytes.size();

        std::vector<uint8_t> secret_key = getSecretKey();
        if (secret_key.empty())
            throw std::runtime_error(worker_name + " Secret key retrieval failed.");

        std::cout << "[STEP 4] Encrypting Kreyvium13 Key Homomorphically..." << std::endl;
        auto key_start = std::chrono::high_resolution_clock::now();
        try
        {
            tfhe_impl_ptr->encrypt_key();
            encryptedKeySizeBytes = tfhe_impl_ptr->getSecretKeyEncryptedSize();
        }
        catch (const std::exception &e)
        {
            encryptedKeySizeBytes = 0;
            noiseBudgetKeyEncrypted = std::numeric_limits<int>::min();

            std::cerr << "[" << worker_name << " ERROR] Key encryption failed: " << e.what() << std::endl;
            throw std::runtime_error(worker_name + " Key encryption failed: " + std::string(e.what())); // Re-throw
        }
        auto key_end = std::chrono::high_resolution_clock::now();
        keyEncryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(key_end - key_start);
        std::cout << "[TIMER] Key encryption time: " << keyEncryptTime.count() << " ms" << std::endl;
        std::cout << "[MEASUREMENT] Enc Key Size(B): " << encryptedKeySizeBytes << std::endl;
        std::cout << "[MEASUREMENT] Enc Key Noise Budget(b): " << (noiseBudgetKeyEncrypted == std::numeric_limits<int>::min() ? "N/A" : std::to_string(noiseBudgetKeyEncrypted)) << std::endl;

        std::cout << "[STEP 5] Performing Homomorphic Decryption (HE_decrypt)..." << std::endl;
        auto decrypt_start = std::chrono::high_resolution_clock::now();
        TFHECiphertextVec he_ciphertexts;

        try
        {
            he_ciphertexts = tfhe_impl_ptr->HE_decrypt(cipher_bytes, tfhe_impl_ptr->get_cipher_size_bits());
            heCiphertextCount = he_ciphertexts.size();

            heCiphertextSizeBytes = tfhe_impl_ptr->get_ciphertexts_size_bytes(he_ciphertexts);

            std::cout << "[MEASUREMENT] HE Decrypt Result CT Count: " << heCiphertextCount << std::endl;
            std::cout << "[MEASUREMENT] HE Decrypt Result Total Size(B): " << heCiphertextSizeBytes << std::endl;
            std::cout << "[MEASUREMENT] HE Decrypt Min Noise Budget(b): " << (noiseBudgetAfterHEDecrypt == std::numeric_limits<int>::min() ? "N/A" : std::to_string(noiseBudgetAfterHEDecrypt)) << std::endl;
        }
        catch (const std::exception &e)
        {
            heCiphertextSizeBytes = 0;
            heCiphertextCount = 0;
            noiseBudgetAfterHEDecrypt = std::numeric_limits<int>::min();
            throw std::runtime_error(worker_name + " HE_decrypt failed: " + std::string(e.what()));
        }
        auto decrypt_end = std::chrono::high_resolution_clock::now();
        heDecryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(decrypt_end - decrypt_start);
        std::cout << "[TIMER] HE_decrypt time: " << heDecryptTime.count() << " ms" << std::endl;

        std::cout << "[STEP 5.1] Computing Hamming Weight with computeHammingWeight..." << std::endl;
        auto sum_start = std::chrono::high_resolution_clock::now();
        TFHECiphertextVec hamming_weight_encrypted_bits;

        try
        {

            hamming_weight_encrypted_bits = tfhe_impl_ptr->computeHammingWeight(he_ciphertexts);

            heSumResultCtCount = hamming_weight_encrypted_bits.size();
            heSumResultSizeBytes = tfhe_impl_ptr->get_ciphertexts_size_bytes(hamming_weight_encrypted_bits);

            std::cout << "[MEASUREMENT] HE Sum (popcount) CT Count: " << heSumResultCtCount << std::endl;
            std::cout << "[MEASUREMENT] HE Sum Size(B): " << heSumResultSizeBytes << std::endl;
            std::cout << "[MEASUREMENT] HE Sum Min Noise Budget(b): " << (noiseBudgetAfterSum == std::numeric_limits<int>::min() ? "N/A" : std::to_string(noiseBudgetAfterSum)) << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << "[ERROR] computeHammingWeight failed: " << e.what() << std::endl;

            heSumResultCtCount = 0;
            heSumResultSizeBytes = 0;
            noiseBudgetAfterSum = std::numeric_limits<int>::min();
            if (correctness_status == "UNKNOWN")
                correctness_status = "HE_SUM_ERROR";
        }

        auto sum_end = std::chrono::high_resolution_clock::now();
        heSumTime = std::chrono::duration_cast<std::chrono::milliseconds>(sum_end - sum_start);
        std::cout << "[TIMER] Popcount time: " << heSumTime.count() << " ms" << std::endl;

        {
            auto sum_decrypt_start = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> hamming_weight_result;

            std::cout << "[STEP 5.2] Decrypting the Hamming Weight..." << std::endl;
            try
            {
                hamming_weight_result = tfhe_impl_ptr->decrypt_result(hamming_weight_encrypted_bits);
                std::cout << "[RESULT] HE Hamming weight decrypted: ";
                for (uint8_t b : hamming_weight_result)
                {
                    std::cout << static_cast<int>(b) << " ";
                }
                std::cout << std::endl;

                uint64_t val = reverseBitsToDecimal(hamming_weight_result);
                std::cout << "[RESULT]: " << val << "\n"; // 58
                decrypted_sum_value = val;
            }
            catch (const std::exception &e)
            {
                std::cerr << "[ERROR] Failed to decrypt HE Hamming weight: " << e.what() << std::endl;
                decrypted_sum_value = static_cast<uint64_t>(-1);
                if (correctness_status == "UNKNOWN")
                    correctness_status = "HE_SUM_DECRYPT_ERROR";
            }

            auto sum_decrypt_end = std::chrono::high_resolution_clock::now();
            sumDecryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(sum_decrypt_end - sum_decrypt_start);
            std::cout << "[TIMER] HE Hamming weight decryption time: " << sumDecryptTime.count() << " ms" << std::endl;
        }

        std::cout << "[STEP 6] Performing Final Decryption (of ORIGINAL HE_decrypt result)..." << std::endl;
        auto final_decrypt_start = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> result_bytes;
        try
        {
            result_bytes = tfhe_impl_ptr->decrypt_result(he_ciphertexts);
            finalPlaintextSizeBytes = result_bytes.size();
            if (correctness_status == "UNKNOWN")
                correctness_status = "OK";
        }
        catch (const std::exception &e)
        {
            if (correctness_status == "OK" || correctness_status == "UNKNOWN")
                correctness_status = "FINAL_DECRYPT_ERROR";

            throw std::runtime_error(worker_name + " Final decrypt_result failed: " + std::string(e.what()));
        }
        auto final_decrypt_end = std::chrono::high_resolution_clock::now();
        finalDecryptTime = std::chrono::duration_cast<std::chrono::milliseconds>(final_decrypt_end - final_decrypt_start);
        final_result_hex = bytesToHexString(result_bytes);
        std::cout << "[MEASUREMENT] Final Plaintext Size(B): " << finalPlaintextSizeBytes << std::endl;
        std::cout << "[TIMER] Final decryption time: " << finalDecryptTime.count() << " ms" << std::endl;

        std::cout << "[STEP 7] Verifying Results and Calculating Ground Truth HW..." << std::endl;
        std::cout << "[RESULT] Kreyvium13 final result (hex): " << final_result_hex << std::endl;

        if (!result_bytes.empty())
        {
            ground_truth_sum_value = calculatePlaintextHammingWeight(result_bytes); // Assumes this function exists in Utils
            std::cout << "[VERIFY] Ground Truth Hamming Weight (from plaintext): " << ground_truth_sum_value << std::endl;

            if (decrypted_sum_value != static_cast<uint64_t>(-1))
            {
                hamming_weight_match = (decrypted_sum_value == ground_truth_sum_value);
                std::cout << "[VERIFY] HE Hamming Weight (" << decrypted_sum_value
                          << ") vs Ground Truth (" << ground_truth_sum_value
                          << ") Match: " << (hamming_weight_match ? "YES" : "NO") << std::endl;
                if (!hamming_weight_match && correctness_status == "OK")
                {
                    correctness_status = "HW_MISMATCH";
                }
            }
            else
            {
                std::cout << "[VERIFY] HE Hamming Weight decryption failed or was skipped, cannot compare." << std::endl;
                hamming_weight_match = false;
            }
        }
        else
        {
            std::cout << "[VERIFY] Final plaintext is empty, cannot calculate ground truth Hamming weight." << std::endl;
            ground_truth_sum_value = -1;
        }

        // --- Successful Completion ---
        auto total_end_time = std::chrono::high_resolution_clock::now();
        totalProcessTime = std::chrono::duration_cast<std::chrono::milliseconds>(total_end_time - total_start_time);

        saveMeasurements(
            "measurement/Kreyvium13_tfhe_measurement.csv", // Use correct filename for each handler
            // --- Timers (ms) ---
            keyEncryptTime,
            heDecryptTime,
            heSumTime,
            finalDecryptTime,
            sumDecryptTime,
            totalProcessTime,
            // --- Sizes (Bytes) ---
            inputCiphertextSizeBytes,
            encryptedKeySizeBytes,
            heCiphertextSizeBytes,
            heSumResultSizeBytes,
            finalPlaintextSizeBytes,
            // --- Counts ---
            heCiphertextCount,
            heSumResultCtCount,
            // --- Noise Budgets (bits) ---
            noiseBudgetKeyEncrypted,
            noiseBudgetAfterHEDecrypt,
            noiseBudgetAfterSum,
            // --- Results & Verification ---
            decrypted_sum_value,
            ground_truth_sum_value,
            hamming_weight_match,
            // --- Status & Parameters ---
            correctness_status,
            actual_polyModDegree,
            actual_plainModulusVal,
            actual_coeffModulusInfo,
            actual_securityLevelVal);

        std::cout << "[" << worker_name << "] --- Finished processMessage (" << correctness_status << ") ---" << std::endl;
        return final_result_hex;
    }
    catch (const std::exception &e)
    {
        std::cerr << "[" << worker_name << " ERROR] Unexpected exception: " << e.what() << std::endl;
        if (correctness_status == "UNKNOWN" || correctness_status == "OK")
        {
            std::string error_msg = std::string(e.what()).substr(0, 80);
            std::replace(error_msg.begin(), error_msg.end(), ',', ';');
            correctness_status = "EXCEPTION: " + error_msg;
        }
        auto total_end_time = std::chrono::high_resolution_clock::now();
        totalProcessTime = std::chrono::duration_cast<std::chrono::milliseconds>(total_end_time - total_start_time);
        saveMeasurements(
            "measurement/Kreyvium13_tfhe_measurement.csv",
            // --- Timers (ms) ---
            keyEncryptTime,
            heDecryptTime,
            heSumTime,
            finalDecryptTime,
            sumDecryptTime,
            totalProcessTime,
            // --- Sizes (Bytes) ---
            inputCiphertextSizeBytes,
            encryptedKeySizeBytes,
            heCiphertextSizeBytes,
            heSumResultSizeBytes,
            finalPlaintextSizeBytes,
            // --- Counts ---
            heCiphertextCount,
            heSumResultCtCount,
            // --- Noise Budgets (bits) ---
            noiseBudgetKeyEncrypted,
            noiseBudgetAfterHEDecrypt,
            noiseBudgetAfterSum,
            // --- Results & Verification ---
            decrypted_sum_value,
            ground_truth_sum_value,
            hamming_weight_match,
            // --- Status & Parameters ---
            correctness_status,
            actual_polyModDegree,
            actual_plainModulusVal,
            actual_coeffModulusInfo,
            actual_securityLevelVal);

        return "Error: Unexpected exception occurred.";
    }
}
