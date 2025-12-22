#pragma once
#include "define.h"
#include "Global.h"
#include "PcapManager.h"
class PacketDetect
{
public:
	PacketDetect(std::vector<map<uint32_t, pair<Packet, int>>>&, concurrency::concurrent_queue<uint32_t>&);
	~PacketDetect();

	void packet_detect(const int ThreadID, const pcap_t* adhandle);
	void packet_Reset(const TcpHeader* pTcp, const pcap_t* adhandle);

private:
	std::vector<thread> ThreadPool;
	std::vector<map<uint32_t, pair<Packet, int>>>& m_pWorker_queues;
	concurrency::concurrent_queue<uint32_t>& m_pBlacklist_queue;

	bool bRunnig{ true };
};

