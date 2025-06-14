#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>
#include <sstream> // Needed here for get_tid_ss usage
#include <thread>  // Needed here for std::this_thread
#include <chrono>  // Needed here for saveMeasurements signature
#include <cstdint> // For uint8_t, uint64_t, etc.

// --- Existing Function ---
inline std::stringstream get_tid_ss()
{
    std::stringstream ss;
    ss << std::this_thread::get_id();
    return ss;
}

// --- NEW Helper Function Declarations ---

/**
 * @brief Converts a hexadecimal string representation to a vector of bytes.
 * @param hex The input hexadecimal string (must have even length).
 * @return std::vector<uint8_t> The resulting byte vector.
 * @throws std::invalid_argument if the hex string is invalid or has odd length.
 * @throws std::out_of_range if a hex value is out of range for uint8_t.
 */
std::vector<uint8_t> hexStringToBytes(const std::string &hex);

/**
 * @brief Converts a vector of bytes to its hexadecimal string representation.
 * @param bytes The input byte vector.
 * @return std::string The resulting hexadecimal string.
 */
std::string bytesToHexString(const std::vector<uint8_t> &bytes);

uint64_t calculatePlaintextHammingWeight(const std::vector<uint8_t> &bytes);

uint64_t reverseBitsToDecimal(std::vector<uint8_t> const &data);

// Declaration for saveMeasurements
void saveMeasurements(
    const std::string &filename,
    // Timers (ms)
    std::chrono::milliseconds keyEncryptTime, std::chrono::milliseconds heDecryptTime,
    std::chrono::milliseconds heSumTime, std::chrono::milliseconds finalDecryptTime,
    std::chrono::milliseconds sumDecryptTime, std::chrono::milliseconds totalProcessTime,
    // Sizes (Bytes)
    size_t inputCiphertextSizeBytes, size_t encryptedKeySizeBytes,
    size_t heCiphertextSizeBytes, size_t heSumResultSizeBytes,
    size_t finalPlaintextSizeBytes,
    // Counts
    size_t heCiphertextCount, size_t heSumResultCtCount,
    // Noise Budgets (bits)
    int noiseBudgetKeyEncrypted, int noiseBudgetAfterHEDecrypt, int noiseBudgetAfterSum,
    // Results & Verification
    uint64_t heDecryptedSum, uint64_t groundTruthSum, bool hwMatch,
    const std::string &correctness_status,
    // Parameters
    uint64_t polyModDegree, uint64_t plainModulus,
    const std::string &coeffModulusInfo, int securityLevel);

#endif // UTILS_H