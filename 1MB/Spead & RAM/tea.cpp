#include "common.h"
#include <cryptopp/tea.h> // Include the specific algorithm header

int main() {
    std::cout << "=== TEA Benchmark ===" << std::endl;
    BenchmarkBlockCipher<CryptoPP::TEA>("TEA");
    return 0;
}
