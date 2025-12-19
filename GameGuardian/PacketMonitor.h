#pragma once
#include "define.h"
#include "PcapManager.h"
class PacketMonitor
{
public:

	PacketMonitor();
	~PacketMonitor();

	void packet_capture( const struct pcap_pkthdr* header, const u_char* pkt_data);
	static void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

	void packet_detect(const int ThreadID, const pcap_t* adhandle);
	void packet_Reset(const TcpHeader* pTcp, const pcap_t* adhandle);

private:
	std::vector<thread> ThreadPool;
	concurrency::concurrent_queue<uint32_t> blacklist_queue;
	set<uint32_t> local_blacklist;

	mutex m1[NUM_WORKER_THREADS];
	bool bRunnig{true};
};

