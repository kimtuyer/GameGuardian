#pragma once
#include "define.h"
#include "Global.h"
#include "PcapManager.h"
class PacketDetect
{
public:
	PacketDetect();
	~PacketDetect();

	void packet_detect(const int ThreadID, const pcap_t* adhandle);
	void packet_Reset(const TcpHeader* pTcp, const pcap_t* adhandle);

private:
	std::vector<thread> ThreadPool;

	bool bRunnig{ true };
};

