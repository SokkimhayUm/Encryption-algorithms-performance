#include "common.h"
#include <cryptopp/rsa.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

void BenchmarkRSA() {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(prng, 2048); // 2048-bit RSA key

    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    const size_t maxBlockSize = (2048 / 8) - 2 * (256 / 8) - 2; // 190 bytes
    const size_t dataSize = 16 * 1024; // 16 KB
    const size_t blockCount = dataSize / maxBlockSize;

    std::string plainBlock(maxBlockSize, 'A');
    std::vector<std::string> cipherBlocks(blockCount);
    std::vector<std::string> recoveredBlocks(blockCount);

    CryptoPP::RSAES_OAEP_SHA_Encryptor e(publicKey);
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey);

    size_t memBeforeEnc = getCurrentRSS();

    auto startEnc = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < blockCount; ++i) {
        CryptoPP::StringSource ss(plainBlock, true,
            new CryptoPP::PK_EncryptorFilter(prng, e,
                new CryptoPP::StringSink(cipherBlocks[i])
            )
        );
    }
    auto endEnc = std::chrono::high_resolution_clock::now();

    size_t memAfterEnc = getCurrentRSS();

    auto startDec = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < blockCount; ++i) {
        CryptoPP::StringSource ss(cipherBlocks[i], true,
            new CryptoPP::PK_DecryptorFilter(prng, d,
                new CryptoPP::StringSink(recoveredBlocks[i])
            )
        );
    }
    auto endDec = std::chrono::high_resolution_clock::now();

    size_t memAfterDec = getCurrentRSS();

    bool passed = true;
    for (size_t i = 0; i < blockCount; ++i) {
        if (recoveredBlocks[i] != plainBlock) {
            passed = false;
            break;
        }
    }

    double encTime = std::chrono::duration<double>(endEnc - startEnc).count();
    double decTime = std::chrono::duration<double>(endDec - startDec).count();
    double encThroughput = (dataSize / (1024.0 * 1024.0)) / encTime;
    double decThroughput = (dataSize / (1024.0 * 1024.0)) / decTime;

    std::cout << std::fixed;
    std::cout << "RSA Encryption time: " << std::setprecision(6) << encTime << " sec, "
              << std::setprecision(4) << encThroughput << " MB/s" << std::endl;
    std::cout << "RSA Decryption time: " << std::setprecision(6) << decTime << " sec, "
              << std::setprecision(4) << decThroughput << " MB/s" << std::endl;
    std::cout << "RSA Memory increase after encryption: " << (memAfterEnc - memBeforeEnc) << " KB" << std::endl;
    std::cout << "RSA Memory increase after decryption: " << (memAfterDec - memAfterEnc) << " KB" << std::endl;
    std::cout << "RSA Data size: " << (dataSize / 1024.0) << " KB" << std::endl;
    std::cout << "Data integrity check: " << (passed ? "PASSED" : "FAILED") << std::endl;

    // Logging to file
    std::ofstream logFile("benchmark.log", std::ios::app);
    if (logFile) {
        std::time_t now = std::time(nullptr);
        char* dt = std::ctime(&now);
        dt[strlen(dt) - 1] = '\0'; // Remove newline

        logFile << "[" << dt << "] RSA Benchmark Results\n";
        logFile << "Encryption time: " << std::fixed << std::setprecision(6) << encTime << " sec, "
                << encThroughput << " MB/s\n";
        logFile << "Decryption time: " << std::fixed << std::setprecision(6) << decTime << " sec, "
                << decThroughput << " MB/s\n";
        logFile << "Memory increase after encryption: " << (memAfterEnc - memBeforeEnc) << " KB\n";
        logFile << "Memory increase after decryption: " << (memAfterDec - memAfterEnc) << " KB\n";
        logFile << "Data size: " << (dataSize / 1024.0) << " KB\n";
        logFile << "Data integrity check: " << (passed ? "PASSED" : "FAILED") << "\n\n";
    } else {
        std::cerr << "Failed to open benchmark.log for writing.\n";
    }
}

int main() {
    std::cout << "=== RSA Benchmark ===" << std::endl;
    BenchmarkRSA();
    return 0;
}
