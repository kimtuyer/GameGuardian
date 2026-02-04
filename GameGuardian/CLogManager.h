#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <string>
#include <sstream>
#include <mutex>

class CLogManager {
public:
    static CLogManager& GetInstance() {
        static CLogManager instance;
        return instance;
    }

    // 로그 파일 경로 설정 (기본값: ./GameGuard_Log.txt)
    void SetLogFilePath(const std::string& path) {
        log_path_ = path;
    }

    // 기존 로깅 함수: 타임스탬프, 위변조 유형, 메모리 주소, IP 주소 포함
    void Log(const std::string& tampering_type, uintptr_t memory_address, const std::string& ip_address) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        std::ofstream log_file(log_path_, std::ios_base::app);
        if (!log_file.is_open()) {
            return;
        }

        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::tm now_tm_struct;
        std::tm* now_tm = &now_tm_struct;
        localtime_s(now_tm, &now_time);
        std::ostringstream oss;
        oss << std::put_time(now_tm, "%Y-%m-%d %H:%M:%S") << ", "
            << tampering_type << ", "
            << "0x" << std::hex << memory_address << std::dec << ", "
            << ip_address << std::endl;

        log_file << oss.str();
    }

    // 기존 로깅 함수: 타임스탬프, 위변조 유형, 메모리 주소, IP 주소 포함
    void Log(const std::string& tampering_type, const std::string& mac_address) {
        std::lock_guard<std::mutex> lock(log_mutex_);
        std::ofstream log_file(log_path_, std::ios_base::app);
        if (!log_file.is_open()) {
            return;
        }

        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::tm now_tm_struct;
        std::tm* now_tm = &now_tm_struct;
        localtime_s(now_tm, &now_time);
        std::ostringstream oss;
        oss << std::put_time(now_tm, "%Y-%m-%d %H:%M:%S") << ", "
            << tampering_type << ", "
            << mac_address << std::endl;

        log_file << oss.str();
    }
    // 새로운 로깅 함수: 날짜와 로그 타입만 인자로 받음
    void Log( const std::string& log_type) {
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::tm now_tm_struct;
        std::tm* now_tm = &now_tm_struct;
        localtime_s(now_tm, &now_time);

        std::lock_guard<std::mutex> lock(log_mutex_);
        std::ofstream log_file(log_path_, std::ios_base::app);
        if (!log_file.is_open()) {
            return;
        }

        std::ostringstream oss;
        oss << std::put_time(now_tm, "%Y-%m-%d %H:%M:%S") << ", "
            << log_type << std::endl;

        log_file << oss.str();
    }

private:
    CLogManager() : log_path_("./GameGuard_Log.txt") {}
    ~CLogManager() = default;
    CLogManager(const CLogManager&) = delete;
    CLogManager& operator=(const CLogManager&) = delete;

    std::string log_path_;
    std::mutex log_mutex_;
};
