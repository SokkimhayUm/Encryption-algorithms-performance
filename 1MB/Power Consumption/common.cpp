#include "common.h"
#include <fstream>
#include <iomanip>

void logToCSV(const std::string& algoName, double totalTime, bool passed) {
    std::ofstream file("power_log.csv", std::ios::app); // append mode
    if (!file) {
        std::cerr << "Failed to open power_log.csv for writing.\n";
        return;
    }

    // Write header if file is empty
    static bool header_written = false;
    static std::once_flag header_flag;
    std::call_once(header_flag, [&]() {
        file << "Algorithm,TotalTime(s),DataIntegrity\n";
    });

    file << algoName << ","
         << std::fixed << std::setprecision(6) << totalTime << ","
         << (passed ? "PASSED" : "FAILED") << "\n";
}

// Get current resident set size (VmRSS) in KB
size_t getCurrentRSS() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.compare(0, 6, "VmRSS:") == 0) {
            size_t pos_kb = line.find("kB");
            if (pos_kb != std::string::npos) {
                std::string value = line.substr(6, pos_kb - 6);
                return std::stoi(value);
            }
        }
    }
    return 0;
}
