#ifndef COMMON_H
#define COMMON_H

#include <iostream>
#include <chrono>
#include <fstream>
#include <string>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>

// Get current resident set size (VmRSS) in KB
size_t getCurrentRSS();

// Benchmark template for block ciphers
template<typename Cipher>
void BenchmarkBlockCipher(const std::string& name);

void logToCSV(const std::string& algoName, double totalTime, bool passed);

#include "common.tpp" // Include template implementation

#endif // COMMON_H
