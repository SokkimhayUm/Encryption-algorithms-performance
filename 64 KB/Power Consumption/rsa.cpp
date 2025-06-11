#include "common.h"
#include <cryptopp/rsa.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <chrono>
#include <vector>
#include <iostream>
#include <string>

bool BenchmarkRSA() {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(prng, 2048); // 2048-bit RSA key

    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    const size_t maxBlockSize = (2048 / 8) - 2 * (256 / 8) - 2; // 190 bytes
    const size_t dataSize = 32 * 1024; // 32 KB
    const size_t blockCount = dataSize / maxBlockSize;

    std::string plainBlock(maxBlockSize, 'A');
    std::vector<std::string> cipherBlocks(blockCount);
    std::vector<std::string> recoveredBlocks(blockCount);

    CryptoPP::RSAES_OAEP_SHA_Encryptor e(publicKey);
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(privateKey);

    // Encryption
    for (size_t i = 0; i < blockCount; ++i) {
        CryptoPP::StringSource ss(plainBlock, true,
            new CryptoPP::PK_EncryptorFilter(prng, e,
                new CryptoPP::StringSink(cipherBlocks[i])
            )
        );
    }

    // Decryption
    for (size_t i = 0; i < blockCount; ++i) {
        CryptoPP::StringSource ss(cipherBlocks[i], true,
            new CryptoPP::PK_DecryptorFilter(prng, d,
                new CryptoPP::StringSink(recoveredBlocks[i])
            )
        );
    }

    // Verify data integrity
    for (size_t i = 0; i < blockCount; ++i) {
        if (recoveredBlocks[i] != plainBlock) {
            std::cerr << "Integrity check failed!" << std::endl;
            return false;
        }
    }

    return true;  // passed
}

void MultiRunRSA(int runs = 10) {
    std::cout << "Starting RSA benchmark: " << runs << " runs" << std::endl;
    bool allPassed = true;

    auto start = std::chrono::steady_clock::now();

    for (int i = 0; i < runs; ++i) {
        bool passed = BenchmarkRSA();
        if (!passed) {
            allPassed = false;
            std::cerr << "Run " << i << " failed integrity check!" << std::endl;
        }
    }

    auto end = std::chrono::steady_clock::now();
    double totalTime = std::chrono::duration<double>(end - start).count();

    std::cout << "Total time: " << totalTime << " sec" << std::endl;
    std::cout << "Use your FNB58 to read average power (W)" << std::endl;
    std::cout << "Then compute: Energy (mWh) = AvgPower (W) × " 
              << (totalTime / 3600.0) << " h" << std::endl;

    logToCSV("RSA", totalTime, allPassed);
}

int main() {
    MultiRunRSA(10);
    return 0;
}