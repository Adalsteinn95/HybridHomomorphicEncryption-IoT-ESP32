#include "handlers/LowmcSealHandler.h"
#include "ciphers/lowmc_seal.h"
#include "Utils.h"
#include "ciphers/SEAL_Cipher.h"

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

const std::string &LowmcSealHandler::getResultTopic() const { return result_topic; }
const std::string &LowmcSealHandler::getWorkerName() const { return worker_name; }

std::vector<uint8_t> LowmcSealHandler::getSecretKey()
{
    std::cout << "[" << worker_name << "] Getting Secret Key..." << std::endl;
    std::vector<uint8_t> key = {
        0x0c, 0x7c, 0xc2, 0x27, 0xec, 0xed, 0x1e, 0x4f,
        0x33, 0xdb, 0xe4, 0xab, 0xdd, 0xfb, 0xb3, 0xbd};
    return key;
}

LowmcSealHandler::LowmcSealHandler() : worker_name("LOWMC_SEAL_WORKER")
{
    std::cout << "[Handler Init] Initializing " << worker_name << "..." << std::endl;
    try
    {
        context = nullptr;
        evaluator = nullptr;
        relin_keys = nullptr;
        galois_keys = nullptr;
        loadContextAndKeys();
        if (!context || !evaluator)
        {
            std::string missing = !context ? "Context " : "";
            missing += !evaluator ? "Evaluator " : "";
            throw std::runtime_error(worker_name + " Handler not fully initialized (missing: " + missing + "). Check initialization logs.");
        }
        if (!relin_keys || !galois_keys)
        {
            std::cerr << "[" << worker_name << " Init WARNING] RelinKeys or GaloisKeys were not generated. Cipher operations (specifically Hamming Weight calculation) may fail when called in processMessage." << std::endl;
        }
        std::cout << "[" << worker_name << "] Initialization complete." << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cerr << "[" << worker_name << " Init ERROR] Failed to initialize: " << e.what() << std::endl;
        context = nullptr;
        evaluator = nullptr;
        relin_keys = nullptr;
        galois_keys = nullptr;
        throw std::runtime_error(worker_name + " Initialization failed: " + std::string(e.what()));
    }
}

// --- Context and Key Loading ---
void LowmcSealHandler::loadContextAndKeys()
{
    // Use the member worker_name
    std::cout << "[" << worker_name << "] Creating SEAL parameters programmatically..." << std::endl;
    uint64_t poly_modulus_degree_req = 32768;
    uint64_t plain_modulus_req = 2;
    seal::sec_level_type sec_level = seal::sec_level_type::tc128;

    seal::EncryptionParameters params(seal::scheme_type::bfv);
    params.set_poly_modulus_degree(poly_modulus_degree_req);
    params.set_coeff_modulus(seal::CoeffModulus::BFVDefault(poly_modulus_degree_req, sec_level));
    params.set_plain_modulus(plain_modulus_req);

    try
    {
        context = std::make_shared<seal::SEALContext>(params, true, sec_level);
    }
    catch (const std::exception &e)
    {
        throw std::runtime_error("Failed to create SEALContext: " + std::string(e.what()));
    }
    if (!context->parameters_set())
        throw std::runtime_error("SEAL context parameters check failed.");

    evaluator = std::make_shared<seal::Evaluator>(*context);

    try
    {
        seal::KeyGenerator keygen(*context);
        relin_keys = std::make_shared<seal::RelinKeys>();
        galois_keys = std::make_shared<seal::GaloisKeys>();
        keygen.create_relin_keys(*relin_keys);
        keygen.create_galois_keys(*galois_keys);
    }
    catch (const std::exception &e)
    {
        std::cerr << "[" << worker_name << " WARNING] Failed to generate SEAL keys (relinkeys/galoiskeys): " << e.what() << std::endl;
    }

    std::cout << "[" << worker_name << "] SEAL Context & Evaluator created." << std::endl;
}

std::string LowmcSealHandler::processMessage(const std::string &ciphertext_hex_payload)
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
        size_t total_bits_in_payload = inputCiphertextSizeBytes * 8;

        std::vector<uint8_t> secret_key = getSecretKey();
        if (secret_key.empty())
            throw std::runtime_error(worker_name + " Secret key retrieval failed.");

        std::unique_ptr<LOWMC::LOWMC_256_128_63_14_SEAL> seal_impl_ptr;
        try
        {
            seal_impl_ptr = std::make_unique<LOWMC::LOWMC_256_128_63_14_SEAL>(secret_key, context);
        }
        catch (const std::exception &e)
        {
            throw std::runtime_error(worker_name + " LOWMC construction failed: " + std::string(e.what()));
        }

        try
        {
            SEALParamsInfo params_info = seal_impl_ptr->get_context_params_info();
            actual_polyModDegree = params_info.poly_modulus_degree;
            actual_plainModulusVal = params_info.plain_modulus_value;
            actual_coeffModulusInfo = params_info.coeff_modulus_info;
            actual_securityLevelVal = params_info.security_level_value;
            std::cout << "[" << worker_name << "] Extracted SEAL Parameters: PolyDegree=" << actual_polyModDegree
                      << ", PlainMod=" << actual_plainModulusVal
                      << ", CoeffModBits=" << actual_coeffModulusInfo
                      << ", SecLevel=" << actual_securityLevelVal << std::endl;
        }
        catch (const std::exception &e)
        {
            actual_coeffModulusInfo = "ExtractionError";
            std::cerr << "[" << worker_name << " WARN] Failed to extract some SEAL parameters: " << e.what() << std::endl;
            actual_polyModDegree = 0;
            actual_plainModulusVal = 0;
            actual_securityLevelVal = 0;
        }

        std::cout << "[STEP 4] Encrypting LOWMC Key Homomorphically..." << std::endl;
        auto key_start = std::chrono::high_resolution_clock::now();
        try
        {
            seal_impl_ptr->encrypt_key();
            noiseBudgetKeyEncrypted = seal_impl_ptr->print_noise();
            encryptedKeySizeBytes = seal_impl_ptr->getSecretKeyEncryptedSize();
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
        SEALCipher::e_int he_ciphertexts;

        try
        {
            he_ciphertexts = seal_impl_ptr->HE_decrypt(cipher_bytes, seal_impl_ptr->get_cipher_size_bits());
            heCiphertextCount = he_ciphertexts.size();

            heCiphertextSizeBytes = seal_impl_ptr->get_ciphertexts_size_bytes(he_ciphertexts);

            if (!he_ciphertexts.empty())
            {
                noiseBudgetAfterHEDecrypt = seal_impl_ptr->print_noise(he_ciphertexts);
            }
            else
            {
                noiseBudgetAfterHEDecrypt = std::numeric_limits<int>::min();
                if (correctness_status == "UNKNOWN")
                    correctness_status = "HE_DECRYPT_EMPTY";
                std::cerr << "[" << worker_name << " WARN] HE_decrypt returned an empty ciphertext vector." << std::endl;
            }
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
        SEALCipher::e_int hamming_weight_encrypted_bits;

        try
        {
            if (!he_ciphertexts.empty())
            {
                hamming_weight_encrypted_bits = seal_impl_ptr->computeHammingWeight(he_ciphertexts);

                heSumResultCtCount = hamming_weight_encrypted_bits.size();
                heSumResultSizeBytes = seal_impl_ptr->get_ciphertexts_size_bytes(hamming_weight_encrypted_bits);

                if (!hamming_weight_encrypted_bits.empty())
                {
                    noiseBudgetAfterSum = seal_impl_ptr->print_noise(hamming_weight_encrypted_bits);
                }
                else
                {
                    noiseBudgetAfterSum = std::numeric_limits<int>::min();
                    std::cerr << "[" << worker_name << " WARN] HE sum (popcount) ciphertext vector is empty." << std::endl;
                    if (correctness_status == "UNKNOWN")
                        correctness_status = "HE_SUM_EMPTY_RESULT";
                }

                std::cout << "[MEASUREMENT] HE Sum (popcount) CT Count: " << heSumResultCtCount << std::endl;
                std::cout << "[MEASUREMENT] HE Sum Size(B): " << heSumResultSizeBytes << std::endl;
                std::cout << "[MEASUREMENT] HE Sum Min Noise Budget(b): " << (noiseBudgetAfterSum == std::numeric_limits<int>::min() ? "N/A" : std::to_string(noiseBudgetAfterSum)) << std::endl;
            }
            else
            {
                std::cout << "[DEBUG]   Skipping popcount – empty HE_decrypt result." << std::endl;

                heSumResultCtCount = 0;
                heSumResultSizeBytes = 0;
                noiseBudgetAfterSum = std::numeric_limits<int>::min();
            }
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

            if (!hamming_weight_encrypted_bits.empty())
            {
                std::cout << "[STEP 5.2] Decrypting the Hamming Weight..." << std::endl;
                try
                {
                    hamming_weight_result = seal_impl_ptr->decrypt_result(hamming_weight_encrypted_bits);
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
            }
            else
            {
                std::cout << "[DEBUG] No Hamming weight ciphertext to decrypt (from popcount)." << std::endl;
                decrypted_sum_value = static_cast<uint64_t>(-1);
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
            if (!he_ciphertexts.empty())
            {
                result_bytes = seal_impl_ptr->decrypt_result(he_ciphertexts);
                finalPlaintextSizeBytes = result_bytes.size();
                if (correctness_status == "UNKNOWN")
                    correctness_status = "OK";
            }
            else
            {
                std::cout << "[" << worker_name << " WARN] Skipping final decryption as HE_decrypt result was empty." << std::endl;
                finalPlaintextSizeBytes = 0;
            }
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
        std::cout << "[RESULT] LOWMC final result (hex): " << final_result_hex << std::endl;

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
            "measurement/lowmc_seal_measurement.csv", // Use correct filename for each handler
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
            "measurement/lowmc_seal_measurement.csv",
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