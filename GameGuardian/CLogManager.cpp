//#include <iostream>
//#include <fstream>
//#include <chrono>
//#include <iomanip>
//#include <string>
//#include <sstream>
//#include <mutex>
////#include "CLogManager.h"
//class CLogManager {
//public:
//    static CLogManager& GetInstance() {
//        static CLogManager instance;
//        return instance;
//    }
//
//    void Log(const std::string& tampering_type, uintptr_t memory_address) {
//        std::lock_guard<std::mutex> lock(log_mutex_);
//        std::ofstream log_file("GameGuard_Log.txt", std::ios_base::app);
//        if (!log_file.is_open()) {
//            return;
//        }
//
//        auto now = std::chrono::system_clock::now();
//        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
//        std::tm* now_tm = std::localtime(&now_time);
//
//        std::ostringstream oss;
//        oss << std::put_time(now_tm, "%Y-%m-%d %H:%M:%S") << ", "
//            << tampering_type << ", "
//            << "0x" << std::hex << memory_address << std::dec << std::endl;
//
//        log_file << oss.str();
//    }
//
//private:
//    CLogManager() = default;
//    ~CLogManager() = default;
//    CLogManager(const CLogManager&) = delete;
//    CLogManager& operator=(const CLogManager&) = delete;
//
//    std::mutex log_mutex_;
//};
