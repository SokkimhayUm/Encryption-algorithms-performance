#include "common.h"
#include <cryptopp/tea.h> // Include the specific algorithm header

int main() {
    std::cout << "=== XTEA Benchmark ===" << std::endl;
    BenchmarkBlockCipher<CryptoPP::XTEA>("XTEA");
    return 0;
}
