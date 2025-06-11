#include "common.h"
#include <cryptopp/speck.h> // Include the specific algorithm header

int main() {
    std::cout << "=== SPECK128 Benchmark ===" << std::endl;
    BenchmarkBlockCipher<CryptoPP::SPECK128>("SPECK128");
    return 0;
}
