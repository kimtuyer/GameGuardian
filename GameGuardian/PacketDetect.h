#pragma once
#include "define.h"
#include "Global.h"
#include "PcapManager.h"
#include "DataLoader.h"
#include "SharedContext.h"
class PacketDetect
{
public:
	PacketDetect(std::vector<map<uint32_t, pair<Packet, int>>>&, concurrency::concurrent_queue<uint32_t>&,
		SharedContext&);
	PacketDetect(SharedContext&);
	~PacketDetect();

	void packet_detect(const int ThreadID, const pcap_t* adhandle);
	void packet_Reset(const TcpHeader* pTcp, const u_char* pktdata,const pcap_t* adhandle);

private:
	std::vector<thread> ThreadPool;
	/*std::vector<map<uint32_t, pair<Packet, int>>>& m_pWorker_queues;
	concurrency::concurrent_queue<uint32_t>& m_pBlacklist_queue;*/

	//const NetworkConfig& m_config;
	SharedContext& ctx; // ÂüÁ¶
	bool bRunnig{ true };
};

