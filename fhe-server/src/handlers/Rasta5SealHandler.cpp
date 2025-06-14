#include "handlers/Rasta5SealHandler.h"
#include "ciphers/rasta_5_seal.h"
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

const std::string &Rasta5SealHandler::getResultTopic() const { return result_topic; }
const std::string &Rasta5SealHandler::getWorkerName() const { return worker_name; }

std::vector<uint8_t> Rasta5SealHandler::getSecretKey()
{
    std::vector<uint8_t> key = {
        0x76, 0xad, 0x7b, 0x3f, 0x23, 0xe9, 0x58, 0x09,
        0x47, 0x7c, 0xb8, 0x14, 0xcc, 0x35, 0xec, 0x1e,
        0xa6, 0x1e, 0xba, 0xfe, 0x80, 0x43, 0x22, 0x62,
        0x87, 0x65, 0x59, 0x58, 0x56, 0x2e, 0x6c, 0x98,
        0x6e, 0x45, 0xdc, 0xed, 0x34, 0x43, 0x0d, 0xc7,
        0x87, 0x13, 0x0c, 0x04, 0x73, 0x91, 0xbd, 0xfe,
        0x34, 0x17, 0x4c, 0xee, 0xc7, 0x44, 0x85, 0x99,
        0xe2, 0x14, 0xe1, 0x55, 0xd3, 0x70, 0x14, 0xa4,
        0xdb, 0x20};
    return key;
}

Rasta5SealHandler::Rasta5SealHandler() : worker_name("RASTA5_SEAL_WORKER")
{
    try
    {
        loadContextAndKeys();
        if (!context || !evaluator)
        {
            std::string missing = !context ? "Context " : "";
            missing += !evaluator ? "Evaluator " : "";
            throw std::runtime_error(worker_name + " Handler not fully initialized (missing: " + missing + "). Check initialization logs.");
        }
    }
    catch (const std::exception &e)
    {
        context = nullptr;
        evaluator = nullptr;
        relin_keys = nullptr;
        galois_keys = nullptr;
        throw std::runtime_error(worker_name + " Initialization failed: " + std::string(e.what()));
    }
}
// --- Context and Key Loading ---
void Rasta5SealHandler::loadContextAndKeys()
{
    // Use the member worker_name
    std::cout << "[" << worker_name << "] Creating SEAL parameters programmatically..." << std::endl;
    uint64_t poly_modulus_degree_req = 16384;
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

std::string Rasta5SealHandler::processMessage(const std::string &ciphertext_hex_payload)
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
        size_t total_bits_in_payload = cipher_bytes.size();

        std::vector<uint8_t> secret_key = getSecretKey();
        if (secret_key.empty())
            throw std::runtime_error(worker_name + " Secret key retrieval failed.");

        std::unique_ptr<RASTA_5::RASTA_128_SEAL> seal_impl_ptr;
        try
        {
            seal_impl_ptr = std::make_unique<RASTA_5::RASTA_128_SEAL>(secret_key, context);
        }
        catch (const std::exception &e)
        {
            throw std::runtime_error(worker_name + " RASTA6 construction failed: " + std::string(e.what()));
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

        std::cout << "[STEP 4] Encrypting RASTA5 Key Homomorphically..." << std::endl;
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

            if (!hamming_weight_encrypted_bits.empty())
            {
                std::cout << "[STEP 5.2] Decrypting the Hamming Weight..." << std::endl;
                try
                {
                    seal_impl_ptr->decrypt(hamming_weight_encrypted_bits, decrypted_sum_value);
                    std::cout << "[RESULT] HE Hamming weight decrypted: " << decrypted_sum_value << std::endl;
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
        std::cout << "[RESULT] RASTA5 final result (hex): " << final_result_hex << std::endl;

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
            "measurement/rasta5_seal_measurement.csv", // Use correct filename for each handler
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
            "measurement/rasta5_seal_measurement.csv",
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