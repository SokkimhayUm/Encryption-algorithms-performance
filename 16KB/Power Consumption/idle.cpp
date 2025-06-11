#include <iostream>
#include <chrono>
#include <thread>

int main() {
    const int idle_seconds = 120; // 2 minute

    std::cout << "Starting IDLE test for " << idle_seconds << " seconds..." << std::endl;
    auto start = std::chrono::steady_clock::now();

    std::this_thread::sleep_for(std::chrono::seconds(idle_seconds));

    auto end = std::chrono::steady_clock::now();
    double duration = std::chrono::duration<double>(end - start).count();

    std::cout << "IDLE test completed: " << duration << " sec" << std::endl;
    std::cout << "Use FNB58 to measure average idle power (W)" << std::endl;
    std::cout << "Then compute: Energy (mWh) = AvgIdlePower × " 
              << (duration / 3600.0) << " h" << std::endl;

    return 0;
}
