#pragma once
#include "PcapManager.h"
extern PcapManager PcapAdmin;
extern std::vector<map<uint32_t, pair<Packet, int>>> worker_queues;
