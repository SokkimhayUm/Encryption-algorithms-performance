#include "common.h"
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <iostream>
#include <chrono>
#include <cstring> // for memcmp

void BenchmarkAES() {
    using namespace CryptoPP;

    const int NUM_RUNS = 1000;
    const size_t dataSize = 256 * 1024; // 256 KB

    AutoSeededRandomPool prng;
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    SecByteBlock plaintext(dataSize), encrypted(dataSize), decrypted(dataSize);
    prng.GenerateBlock(plaintext, plaintext.size());

    AES::Encryption aesEnc;
    aesEnc.SetKey(key, key.size());

    AES::Decryption aesDec;
    aesDec.SetKey(key, key.size());

    std::cout << "Starting AES benchmark: " << NUM_RUNS << " runs\n";

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < NUM_RUNS; ++i) {
        for (size_t offset = 0; offset < dataSize; offset += AES::BLOCKSIZE) {
            aesEnc.ProcessAndXorBlock(plaintext + offset, nullptr, encrypted + offset);
        }

        for (size_t offset = 0; offset < dataSize; offset += AES::BLOCKSIZE) {
            aesDec.ProcessAndXorBlock(encrypted + offset, nullptr, decrypted + offset);
        }
    }
    auto end = std::chrono::high_resolution_clock::now();

    bool passed = std::memcmp(plaintext.data(), decrypted.data(), dataSize) == 0;

    double totalTime = std::chrono::duration<double>(end - start).count();
    double avgTime = totalTime / NUM_RUNS;

    std::cout << std::fixed;
    std::cout << "Total time: " << totalTime << " sec\n";
    std::cout << "Avg time per run: " << avgTime << " sec\n";
    std::cout << "Use your FNB58 to read average power (W)\n";
    std::cout << "Then compute: Energy (mWh) = AvgPower (W) × "
              << (totalTime / 3600.0) << " h" << std::endl;
    std::cout << "Data integrity check: " << (passed ? "PASSED" : "FAILED") << std::endl;

    logToCSV("AES", totalTime, passed);
}

int main() {
    std::cout << "=== AES Benchmark ===" << std::endl;
    BenchmarkAES();
    return 0;
}
