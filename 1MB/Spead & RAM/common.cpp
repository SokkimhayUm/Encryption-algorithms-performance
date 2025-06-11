#include "common.h"

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
