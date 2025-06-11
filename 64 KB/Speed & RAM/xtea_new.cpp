#include "common.h"
#include <cryptopp/tea.h>

int main() {
    std::cout << "=== XTEA Benchmark ===" << std::endl;
    BenchmarkBlockCipher<CryptoPP::XTEA>("XTEA");
    return 0;
}
