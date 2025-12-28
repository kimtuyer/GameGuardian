#pragma once
#include "define.h"
#include "DataLoader.h"

// 워커 스레드 1명이 가질 전용 데이터 세트
struct WorkerContext {
    // 1. 전용 큐
    std::map<uint32_t, std::pair<Packet, PacketCount>> packetlist;

    // 2. 전용 락과 알림벨 (이 스레드만 쳐다봄)
    std::mutex q_mutex;
    std::condition_variable q_cv;

    // 복사 금지 (mutex, cv 때문)
    WorkerContext() = default;
    WorkerContext(const WorkerContext&) = delete;
    WorkerContext& operator=(const WorkerContext&) = delete;
};

// 워커 스레드들이 공유할 모든 자원
struct SharedContext {
    // 1. 데이터 큐
    //std::vector<std::map<uint32_t, std::pair<Packet, int>>> worker_queues;
    std::vector<std::unique_ptr<WorkerContext>> workers;

    concurrency::concurrent_queue<uint32_t> blacklist_queue;

    // 2. 동기화 객체 (Condition Variable 필수품)
    // cpu코어간에 같은 캐시라인에 속해 False Sharing 성능 우려 있음. 
    //mutex m1[NUM_WORKER_THREADS];
    //std::condition_variable cv[NUM_WORKER_THREADS];

    // 3. 설정 파일
    const NetworkConfig config;

    // 생성자 (설정 파일 초기화 등)
    SharedContext(const NetworkConfig& cfg) : config(cfg) {

        for (int i = 0; i < NUM_WORKER_THREADS; ++i) {
            workers.push_back(std::make_unique<WorkerContext>());
        }
    }
};