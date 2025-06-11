#include <iostream>
#include <vector>
#include <random>
#include <chrono>
#include <cstring>
#include <iomanip>

class PRESENT {
private:
    static const uint8_t S_BOX[16];
    static const uint8_t INV_S_BOX[16];
    static const uint8_t P_LAYER[64];
    static const uint8_t INV_P_LAYER[64];
    static constexpr int NUM_ROUNDS = 32;

    uint64_t round_keys[NUM_ROUNDS + 1];  // Fixed size

    inline uint64_t apply_sbox(uint64_t state, const uint8_t s_box_table[16]) const {
        uint64_t new_state = 0;
        for (int i = 0; i < 16; ++i) {
            uint8_t nibble = (state >> (i * 4)) & 0xF;
            new_state |= (uint64_t)s_box_table[nibble] << (i * 4);
        }
        return new_state;
    }

    inline uint64_t apply_p_layer(uint64_t state, const uint8_t p_layer_table[64]) const {
        uint64_t new_state = 0;
        for (int i = 0; i < 64; ++i)
            if ((state >> p_layer_table[i]) & 1ULL)
                new_state |= (1ULL << i);
        return new_state;
    }

    void generateRoundKeys(const uint8_t* key) {
        uint64_t K_msb = 0, K_lsb = 0;
        for (int j = 0; j < 8; ++j) {
            K_msb = (K_msb << 8) | key[j];
            K_lsb = (K_lsb << 8) | key[j + 8];
        }
        round_keys[0] = K_msb;

        for (int i = 1; i <= NUM_ROUNDS; ++i) {
            uint64_t temp_msb = K_msb;
            uint64_t temp_lsb = K_lsb;
            K_msb = (temp_msb << 8) | (temp_lsb >> 56);
            K_lsb = (temp_lsb << 8) | (temp_msb >> 56);

            uint8_t sbox_in = (K_msb >> 60) & 0xF;
            K_msb = (K_msb & 0x0FFFFFFFFFFFFFFFULL) | ((uint64_t)S_BOX[sbox_in] << 60);

            uint8_t bits = ((K_msb & 0x7ULL) << 2) | ((K_lsb >> 62) & 0x3ULL);
            bits ^= i;
            K_msb = (K_msb & ~0x7ULL) | ((bits >> 2) & 0x7ULL);
            K_lsb = (K_lsb & ~(0x3ULL << 62)) | ((uint64_t)(bits & 0x3ULL) << 62);

            round_keys[i] = K_msb;
        }
    }

public:
    static constexpr size_t KEYLENGTH = 16;
    static constexpr size_t BLOCKSIZE = 8;

    PRESENT(const uint8_t* key_bytes) {
        generateRoundKeys(key_bytes);
    }

    void encryptBlock(uint64_t& block) const {
        block ^= round_keys[0];
        for (int r = 1; r <= NUM_ROUNDS; ++r) {
            block = apply_sbox(block, S_BOX);
            block = apply_p_layer(block, P_LAYER);
            block ^= round_keys[r];
        }
    }

    void decryptBlock(uint64_t& block) const {
        for (int r = NUM_ROUNDS; r >= 1; --r) {
            block ^= round_keys[r];
            block = apply_p_layer(block, INV_P_LAYER);
            block = apply_sbox(block, INV_S_BOX);
        }
        block ^= round_keys[0];
    }

    void encryptCTR(uint8_t* data, size_t length, uint64_t nonce) const {
        uint64_t counter = 0;
        for (size_t offset = 0; offset < length; offset += BLOCKSIZE) {
            uint64_t stream_block = nonce + counter++;
            encryptBlock(stream_block);
            size_t block_len = std::min(BLOCKSIZE, length - offset);
            for (size_t i = 0; i < block_len; ++i)
                data[offset + i] ^= reinterpret_cast<uint8_t*>(&stream_block)[i];
        }
    }

    void decryptCTR(uint8_t* data, size_t length, uint64_t nonce) const {
        encryptCTR(data, length, nonce); // CTR decryption = encryption
    }
};

// Constants
const uint8_t PRESENT::S_BOX[16] = {
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};
const uint8_t PRESENT::INV_S_BOX[16] = {
    0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA
};
const uint8_t PRESENT::P_LAYER[64] = {
     0, 16, 32, 48,  1, 17, 33, 49,  2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,  6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};
const uint8_t PRESENT::INV_P_LAYER[64] = {
     0,  4,  8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
     1,  5,  9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
     2,  6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
     3,  7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63
};

int main() {
    const size_t dataSize = 16 * 1024; // 16 KB
    const int runs = 1000;

    std::vector<uint8_t> key(16), plaintext(dataSize), ciphertext(dataSize), decrypted(dataSize);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (auto& byte : key) byte = dis(gen);
    for (auto& byte : plaintext) byte = dis(gen);

    PRESENT cipher(key.data());

    std::cout << "=== PRESENT Power Benchmark ===\n";
    std::cout << "Running " << runs << " full encryption + decryption runs (16 KB each)\n";

    double totalEncTime = 0.0;
    double totalDecTime = 0.0;
    bool allPassed = true;

    for (int i = 0; i < runs; ++i) {
        std::memcpy(ciphertext.data(), plaintext.data(), dataSize);
        uint64_t nonce = static_cast<uint64_t>(rd());

        auto startEnc = std::chrono::high_resolution_clock::now();
        cipher.encryptCTR(ciphertext.data(), dataSize, nonce);
        auto endEnc = std::chrono::high_resolution_clock::now();
        totalEncTime += std::chrono::duration<double>(endEnc - startEnc).count();

        std::memcpy(decrypted.data(), ciphertext.data(), dataSize);

        auto startDec = std::chrono::high_resolution_clock::now();
        cipher.decryptCTR(decrypted.data(), dataSize, nonce);
        auto endDec = std::chrono::high_resolution_clock::now();
        totalDecTime += std::chrono::duration<double>(endDec - startDec).count();

        if (std::memcmp(plaintext.data(), decrypted.data(), dataSize) != 0) {
            allPassed = false;
            break;
        }
    }

    double totalTime = totalEncTime + totalDecTime;
    double avgTime = totalTime / runs;

    std::cout << std::fixed << std::setprecision(6);
    std::cout << "Total encryption time: " << totalEncTime << " sec\n";
    std::cout << "Total decryption time: " << totalDecTime << " sec\n";
    std::cout << "Total time:           " << totalTime << " sec\n";
    std::cout << "Average time per run: " << avgTime << " sec\n";

    std::cout << "Use your FNB58 to read average power (W)\n";
    std::cout << "Then compute: Energy (mWh) = AvgPower (W) × "
              << (totalTime / 3600.0) << " h\n";

    std::cout << "Data integrity check: " << (allPassed ? "PASSED" : "FAILED") << "\n";

    return allPassed ? 0 : 1;
}