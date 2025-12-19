#pragma once
#include "define.h"


class PcapManager
{

public:
	PcapManager();
	~PcapManager();

	bool SetDevice();
	bool CreateHandle(const pcap_if_t* d, const pcap_if_t* alldevs, char errbuf[PCAP_ERRBUF_SIZE]);
	
	const pcap_t* GetHandle()
	{
		return adhandle;
	}



private:
	pcap_t* adhandle{};

};

