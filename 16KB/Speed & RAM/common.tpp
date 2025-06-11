#include "common.h"
#include <cryptopp/filters.h>
#include <iomanip> // For std::setprecision
#include <ctime>   // For timestamp

template<typename Cipher>
void BenchmarkBlockCipher(const std::string& name) {
    CryptoPP::AutoSeededRandomPool prng;
    const size_t dataSize = 16 * 1024; // 16 KB
    const int iterations = 1000;

    CryptoPP::SecByteBlock key(Cipher::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    CryptoPP::SecByteBlock plaintext(dataSize), encrypted(dataSize), decrypted(dataSize);
    prng.GenerateBlock(plaintext, plaintext.size());

    typename Cipher::Encryption enc;
    enc.SetKey(key, key.size());

    typename Cipher::Decryption dec;
    dec.SetKey(key, key.size());

    size_t memBeforeEnc = getCurrentRSS();

    auto startEnc = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < iterations; ++iter) {
        for (size_t i = 0; i < dataSize; i += enc.BlockSize()) {
            enc.ProcessAndXorBlock(plaintext + i, nullptr, encrypted + i);
        }
    }
    auto endEnc = std::chrono::high_resolution_clock::now();

    size_t memAfterEnc = getCurrentRSS();

    auto startDec = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < iterations; ++iter) {
        for (size_t i = 0; i < dataSize; i += dec.BlockSize()) {
            dec.ProcessAndXorBlock(encrypted + i, nullptr, decrypted + i);
        }
    }
    auto endDec = std::chrono::high_resolution_clock::now();

    size_t memAfterDec = getCurrentRSS();

    double encTime = std::chrono::duration<double>(endEnc - startEnc).count();
    double decTime = std::chrono::duration<double>(endDec - startDec).count();
    bool passed = memcmp(plaintext.data(), decrypted.data(), dataSize) == 0;

    // Adjusted throughput (total data processed over time)
    double throughputEnc = ((dataSize * iterations) / (1024.0 * 1024.0)) / encTime;
    double throughputDec = ((dataSize * iterations) / (1024.0 * 1024.0)) / decTime;

    // Console Output
    std::cout << name << " Encryption time (1000x): " << encTime << " sec, "
              << throughputEnc << " MB/s" << std::endl;
    std::cout << name << " Decryption time (1000x): " << decTime << " sec, "
              << throughputDec << " MB/s" << std::endl;

    std::cout << name << " Memory increase after encryption: " << (memAfterEnc - memBeforeEnc) << " KB" << std::endl;
    std::cout << name << " Memory increase after decryption: " << (memAfterDec - memAfterEnc) << " KB" << std::endl;

    std::cout << name << " Data buffer size: " << (dataSize / (1024.0)) << " KB" << std::endl;
    std::cout << "Data integrity check: " << (passed ? "PASSED" : "FAILED") << "\n" << std::endl;

    // Log to file
    std::ofstream logFile("benchmark.log", std::ios::app);
    if (logFile) {
        std::time_t now = std::time(nullptr);
        char* dt = std::ctime(&now);
        dt[strlen(dt) - 1] = '\0'; // Remove newline

        logFile << "[" << dt << "] " << name << " Benchmark Results (1000 iterations)\n";
        logFile << "Encryption time: " << std::fixed << std::setprecision(6) << encTime << " sec, "
                << throughputEnc << " MB/s\n";
        logFile << "Decryption time: " << std::fixed << std::setprecision(6) << decTime << " sec, "
                << throughputDec << " MB/s\n";
        logFile << "Memory increase after encryption: " << (memAfterEnc - memBeforeEnc) << " KB\n";
        logFile << "Memory increase after decryption: " << (memAfterDec - memAfterEnc) << " KB\n";
        logFile << "Data buffer size: " << (dataSize / (1024.0)) << " KB\n";
        logFile << "Data integrity check: " << (passed ? "PASSED" : "FAILED") << "\n\n";
    } else {
        std::cerr << "Failed to open benchmark.log for writing.\n";
    }
}
