#include "common.h"
#include <cryptopp/tea.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <chrono>
#include <iostream>
#include <cstring>

void BenchmarkXTEA() {
    using namespace CryptoPP;

    const int NUM_RUNS = 100;
    const size_t dataSize = 1024 * 1024;

    AutoSeededRandomPool prng;
    SecByteBlock key(XTEA::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    SecByteBlock plaintext(dataSize), encrypted(dataSize), decrypted(dataSize);
    prng.GenerateBlock(plaintext, plaintext.size());

    XTEA::Encryption enc;
    enc.SetKey(key, key.size());

    XTEA::Decryption dec;
    dec.SetKey(key, key.size());

    std::cout << "Starting XTEA benchmark: " << NUM_RUNS << " runs\n";

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < NUM_RUNS; ++i) {
        for (size_t offset = 0; offset < dataSize; offset += enc.BlockSize())
            enc.ProcessAndXorBlock(plaintext + offset, nullptr, encrypted + offset);

        for (size_t offset = 0; offset < dataSize; offset += dec.BlockSize())
            dec.ProcessAndXorBlock(encrypted + offset, nullptr, decrypted + offset);
    }
    auto end = std::chrono::high_resolution_clock::now();

    bool passed = std::memcmp(plaintext.data(), decrypted.data(), dataSize) == 0;
    double totalTime = std::chrono::duration<double>(end - start).count();

    std::cout << "Total time: " << totalTime << " sec\n";
    std::cout << "Use your FNB58 to read average power (W)\n";
    std::cout << "Then compute: Energy (mWh) = AvgPower (W) × "
              << (totalTime / 3600.0) << " h" << std::endl;
    std::cout << "Data integrity check: " << (passed ? "PASSED" : "FAILED") << std::endl;
    
    logToCSV("XTEA", totalTime, passed);
}

int main() {
    std::cout << "=== XTEA Benchmark ===" << std::endl;
    BenchmarkXTEA();
    return 0;
}
