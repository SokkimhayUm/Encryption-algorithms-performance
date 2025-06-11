#include "common.h"
#include <cryptopp/blowfish.h> // Include the specific algorithm header

int main() {
    std::cout << "=== Blowfish Benchmark ===" << std::endl;
    BenchmarkBlockCipher<CryptoPP::Blowfish>("Blowfish");
    return 0;
}
