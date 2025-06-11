#include "common.h"
#include <cryptopp/aes.h> // Include the specific algorithm header

int main() {
    std::cout << "=== AES Benchmark ===" << std::endl;
    BenchmarkBlockCipher<CryptoPP::AES>("AES");
    return 0;
}
