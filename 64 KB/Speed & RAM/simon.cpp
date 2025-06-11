#include "common.h"
#include <cryptopp/simon.h> // Include the specific algorithm header

int main() {
    std::cout << "=== SIMON128 Benchmark ===" << std::endl;
    BenchmarkBlockCipher<CryptoPP::SIMON128>("SIMON128");
    return 0;
}
