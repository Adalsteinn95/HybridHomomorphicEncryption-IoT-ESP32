#include "Utils.h" // Include the header with declarations
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>   // For std::hex, std::setw, std::setfill
#include <stdexcept> // For std::invalid_argument, std::out_of_range
#include <fstream>   // For std::ofstream
#include <chrono>    // For std::chrono types
#include <ctime>     // For std::gmtime, std::time_t
#include <limits>    // For std::numeric_limits
#include <iostream>  // For std::cerr
#include <algorithm> // For std::replace

// --- NEW Helper Function Definitions ---

std::vector<uint8_t> hexStringToBytes(const std::string &hex)
{
    if (hex.length() % 2 != 0)
    {
        throw std::invalid_argument("Hex string must have an even length");
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (unsigned int i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        try
        {
            unsigned long long val = std::stoull(byteString, nullptr, 16);
            if (val > std::numeric_limits<uint8_t>::max())
            {
                throw std::out_of_range("Hex value out of range for uint8_t: " + byteString);
            }
            bytes.push_back(static_cast<uint8_t>(val));
        }
        catch (const std::invalid_argument &e)
        {
            throw std::invalid_argument("Invalid character found in hex string: " + byteString);
        }
        catch (const std::out_of_range &e)
        {
            // Catch potential overflow from stoull itself, though check above is more specific
            throw std::out_of_range("Hex value out of range during conversion: " + byteString);
        }
    }
    return bytes;
}

std::string bytesToHexString(const std::vector<uint8_t> &bytes)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto &byte : bytes)
    {
        ss << std::setw(2) << static_cast<int>(byte); // Cast to int ensures it's interpreted as number
    }
    return ss.str();
}

uint64_t calculatePlaintextHammingWeight(const std::vector<uint8_t> &bytes)
{
    // Implementation from previous response
    uint64_t count = 0;
    for (uint8_t b : bytes)
    {
        count += __builtin_popcount(b); // Use builtin if available and not C++20
    }
    return count;
}

void saveMeasurements(
    const std::string &filename,
    // Timers (ms) - Using clearer names matching the handler
    std::chrono::milliseconds keyEncryptTime, std::chrono::milliseconds heDecryptTime,
    std::chrono::milliseconds heSumTime, std::chrono::milliseconds finalDecryptTime,
    std::chrono::milliseconds sumDecryptTime, std::chrono::milliseconds totalProcessTime,
    // Sizes (Bytes) - Added input and final plaintext sizes
    size_t inputCiphertextSizeBytes, size_t encryptedKeySizeBytes,
    size_t heCiphertextSizeBytes, size_t heSumResultSizeBytes,
    size_t finalPlaintextSizeBytes,
    // Counts - Added CT counts
    size_t heCiphertextCount, size_t heSumResultCtCount,
    // Noise Budgets (bits)
    int noiseBudgetKeyEncrypted, int noiseBudgetAfterHEDecrypt, int noiseBudgetAfterSum,
    // Results & Verification - Added HW results and match flag
    uint64_t heDecryptedSum, uint64_t groundTruthSum, bool hwMatch,
    const std::string &correctness_status,
    // Parameters
    uint64_t polyModDegree, uint64_t plainModulus,
    const std::string &coeffModulusInfo, int securityLevel)
{
    std::ofstream outputFile;
    // Assuming 'measurement' directory exists relative to execution path
    outputFile.open(filename, std::ios::app);

    if (!outputFile.is_open())
    {
        std::cerr << "[saveMeasurements ERROR] Failed to open measurement file: " << filename << std::endl;
        return;
    }

    // Check if file is empty to write header (using the original method)
    outputFile.seekp(0, std::ios::end);
    bool writeHeader = (outputFile.tellp() == 0);

    // Define header string with new and updated column names
    const std::string header =
        "Timestamp,"
        "KeyEncryptTime(ms),HEDecryptTime(ms),HESumTime(ms),"
        "FinalDecryptTime(ms),SumDecryptTime(ms),"
        "TotalProcessTime(ms),"
        "InputSize(B),"
        "EncKeySize(B),"
        "HEDecryptOutSize(B),"
        "HESumOutSize(B),"
        "FinalPlaintextSize(B),"
        "HEDecryptCTCount,"
        "HESumCTCount,"
        "NoiseBudgetEncKey(b),"
        "NoiseBudgetAfterDecrypt(b),"
        "NoiseBudgetAfterSum(b),"
        "HEDecryptedSum,"
        "GroundTruthSum,"
        "HW_Match,"
        "Status,"
        "PolyModDegree,PlainModulus,CoeffModulusInfo,SecurityLevel";

    if (writeHeader)
    {
        outputFile << header << std::endl;
        if (!outputFile.good())
        {
            std::cerr << "[saveMeasurements ERROR] Failed to write header to file: " << filename << std::endl;
            outputFile.close();
            return;
        }
    }

    // Get current timestamp (using the original method)
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);

    std::tm now_tm = *std::gmtime(&now_c);

    std::string safe_status = correctness_status;
    std::replace(safe_status.begin(), safe_status.end(), ',', ';');
    std::string safe_coeff_info = coeffModulusInfo;
    std::replace(safe_coeff_info.begin(), safe_coeff_info.end(), ',', ';');
    // Remove brackets if they were added for display elsewhere
    std::replace(safe_coeff_info.begin(), safe_coeff_info.end(), '[', ' ');
    std::replace(safe_coeff_info.begin(), safe_coeff_info.end(), ']', ' ');

    outputFile << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S %Z") << "," // Timestamp
                                                                        // Timers
               << keyEncryptTime.count() << "," << heDecryptTime.count() << "," << heSumTime.count() << ","
               << finalDecryptTime.count() << "," << sumDecryptTime.count() << "," << totalProcessTime.count() << ","
               // Sizes
               << inputCiphertextSizeBytes << ","
               << encryptedKeySizeBytes << ","
               << heCiphertextSizeBytes << "," << heSumResultSizeBytes << ","
               << finalPlaintextSizeBytes << ","
               // Counts
               << heCiphertextCount << ","
               << heSumResultCtCount << ","
               // Noise Budgets
               << noiseBudgetKeyEncrypted << "," << noiseBudgetAfterHEDecrypt << "," << noiseBudgetAfterSum << ","
               // HW Results
               << heDecryptedSum << ","
               << groundTruthSum << ","
               << (hwMatch ? "true" : "false") << ","
               // Status & Params
               << "\"" << safe_status << "\","
               << polyModDegree << "," << plainModulus << ","
               << "\"" << safe_coeff_info << "\","
               << securityLevel
               << std::endl;

    if (!outputFile.good())
    {
        std::cerr << "[saveMeasurements ERROR] Failed to write data row to file: " << filename << std::endl;
    }

    outputFile.close();
}

uint64_t reverseBitsToDecimal(std::vector<uint8_t> const &data)
{
    // 1) Flatten into a bit‐vector (MSB→LSB per byte, bytes in order 0…n-1)
    std::vector<uint8_t> bits;
    bits.reserve(data.size() * 8);
    for (uint8_t byte : data)
    {
        for (int b = 7; b >= 0; --b)
        {
            bits.push_back((byte >> b) & 1);
        }
    }

    // 2) Reverse the entire bit‐vector
    std::reverse(bits.begin(), bits.end());

    // 3) Fold into an integer
    uint64_t result = 0;
    for (uint8_t bit : bits)
    {
        result = (result << 1) | bit;
    }
    return result;
}