#pragma once
#include "define.h"
#include "Global.h"
#include "PcapManager.h"
class PacketCapture
{
public:
	PacketCapture();
	~PacketCapture();

	void packet_capture(const struct pcap_pkthdr* header, const u_char* pkt_data);
	static void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
	void Run();

private:
	set<uint32_t> local_blacklist;

	bool bRunnig{ true };
};

