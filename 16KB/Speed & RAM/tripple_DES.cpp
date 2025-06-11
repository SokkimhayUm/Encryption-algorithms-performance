#include "common.h"
#include <cryptopp/des.h> // Include the specific algorithm header

int main() {
    std::cout << "=== Triple DES Benchmark ===" << std::endl;
    BenchmarkBlockCipher<CryptoPP::DES_EDE3>("Triple DES");
    return 0;
}
