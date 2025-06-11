#include "common.h"
#include <cryptopp/filters.h> // For CryptoPP filters

template<typename Cipher>
void BenchmarkBlockCipher(const std::string& name) {
    CryptoPP::AutoSeededRandomPool prng;
    const size_t dataSize = 1024 * 1024; // 1 MB

    CryptoPP::SecByteBlock key(Cipher::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    CryptoPP::SecByteBlock plaintext(dataSize), encrypted(dataSize), decrypted(dataSize);
    prng.GenerateBlock(plaintext, plaintext.size());

    typename Cipher::Encryption enc;
    enc.SetKey(key, key.size());

    typename Cipher::Decryption dec;
    dec.SetKey(key, key.size());

    // Measure memory before encryption
    size_t memBeforeEnc = getCurrentRSS();

    auto startEnc = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < dataSize; i += enc.BlockSize())
        enc.ProcessAndXorBlock(plaintext + i, nullptr, encrypted + i);
    auto endEnc = std::chrono::high_resolution_clock::now();

    // Measure memory after encryption
    size_t memAfterEnc = getCurrentRSS();

    auto startDec = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < dataSize; i += dec.BlockSize())
        dec.ProcessAndXorBlock(encrypted + i, nullptr, decrypted + i);
    auto endDec = std::chrono::high_resolution_clock::now();

    // Measure memory after decryption
    size_t memAfterDec = getCurrentRSS();

    double encTime = std::chrono::duration<double>(endEnc - startEnc).count();
    double decTime = std::chrono::duration<double>(endDec - startDec).count();

    bool passed = memcmp(plaintext.data(), decrypted.data(), dataSize) == 0;

    std::cout << name << " Encryption time: " << encTime << " sec, "
              << (dataSize / (1024.0 * 1024.0)) / encTime << " MB/s" << std::endl;
    std::cout << name << " Decryption time: " << decTime << " sec, "
              << (dataSize / (1024.0 * 1024.0)) / decTime << " MB/s" << std::endl;

    std::cout << name << " Memory increase after encryption: " << (memAfterEnc - memBeforeEnc) << " KB" << std::endl;
    std::cout << name << " Memory increase after decryption: " << (memAfterDec - memAfterEnc) << " KB" << std::endl;

    std::cout << name << " Data buffer size: " << (dataSize / (1024.0 * 1024.0)) << " MB" << std::endl;
    std::cout << "Data integrity check: " << (passed ? "PASSED" : "FAILED") << "\n" << std::endl;
}
