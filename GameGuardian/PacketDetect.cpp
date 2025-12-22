#include "PacketDetect.h"
//#include "Global.h"
PacketDetect::PacketDetect()
{
	for (int i = 0; i < NUM_WORKER_THREADS; i++)
		ThreadPool.push_back(thread(&PacketDetect::packet_detect, this, i, PcapAdmin.GetHandle()));

}

PacketDetect::~PacketDetect()
{
	for (int i = 0; i < NUM_WORKER_THREADS; i++)
		if (ThreadPool[i].joinable())
			ThreadPool[i].join();
}

void PacketDetect::packet_detect(const int ThreadID, const pcap_t* adhandle)
{
	auto last_check_time = std::chrono::steady_clock::now();

	//int size = 500;
	map<uint32_t, pair<Packet, int>> local_IPList;
	map<uint32_t, pair<Packet, int>> accomulate_stat;


	while (bRunnig)
	{
		//1초 주기로 ip별 패킷 카운트 수 초기화
		auto now = std::chrono::steady_clock::now();
		if (chrono::duration_cast<std::chrono::seconds>(now - last_check_time).count() >= 1) {
			last_check_time = now;
			accomulate_stat.clear();
		}
		//printf("--- 1초 경과: 카운트 리셋 ---\n");

		{
			lock_guard<mutex> local_m(m1[ThreadID]);
			if (worker_queues[ThreadID].empty())
			{
				this_thread::yield();
				continue;
			}
			local_IPList.swap(worker_queues[ThreadID]);
		}

		for (auto [ip, data] : local_IPList)
		{
			accomulate_stat[ip].second += data.second;

			auto packet = data.first;

			if (packet.m_pkt_data.empty())
				continue;

			accomulate_stat[ip].first = packet;

			u_char* raw_ptr = packet.m_pkt_data.data();

			EtherHeader* pEther = (EtherHeader*)raw_ptr;
			IpHeader* pIpHeader = (IpHeader*)(raw_ptr + sizeof(EtherHeader));

			if (packet.m_pkt_data.size() < sizeof(EtherHeader) + 20) {
				continue; // 최소한의 IP 헤더 길이도 안 되면 패스
			}

			int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
			TcpHeader* pTcp =
				(TcpHeader*)(raw_ptr + sizeof(EtherHeader) + ipHeaderLen);

			printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
				pIpHeader->srcIp[0], pIpHeader->srcIp[1],
				pIpHeader->srcIp[2], pIpHeader->srcIp[3],
				ntohs(pTcp->srcPort),
				pIpHeader->dstIp[0], pIpHeader->dstIp[1],
				pIpHeader->dstIp[2], pIpHeader->dstIp[3],
				ntohs(pTcp->dstPort)
			);

			int tcpHeaderSize = ((pTcp->data >> 4 & 0x0F) * 4);
			char* pPayload = (char*)(raw_ptr + sizeof(EtherHeader) +
				ipHeaderLen + tcpHeaderSize);

			int Segmentsize = ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize;
			printf("Segment size: %d(Frame length: %d)\n",
				Segmentsize,
				packet.m_pheader.len);

			/*if (accomulate_stat[ip].second < 100)
				continue;*/

			//클라->서버 ,서버->클라, 클라->서버 ACK 보내는 마지막 패킷 캡쳐
			if (pTcp->flags == 0x010) // Flags 비트 값이 0x010 (ACK)일 경우에만 읽고 탐지
			{
				packet_Reset(pTcp, adhandle);
				blacklist_queue.push(ip);
			}
		}
		local_IPList.clear();
	}
}

void PacketDetect::packet_Reset(const TcpHeader* pTcp, const pcap_t* adhandle)
{
	unsigned char frameData[1514] = { 0 };
	int msgSize = 0;
	EtherHeader* pEtherHeader = (EtherHeader*)frameData;
	pEtherHeader->dstMac[0] = 0x00; pEtherHeader->dstMac[1] = 0x0C;
	pEtherHeader->dstMac[2] = 0x29; pEtherHeader->dstMac[3] = 0x72;
	pEtherHeader->dstMac[4] = 0x01; pEtherHeader->dstMac[5] = 0x51;

	pEtherHeader->srcMac[0] = 0x00; pEtherHeader->srcMac[1] = 0x50;
	pEtherHeader->srcMac[2] = 0x56; pEtherHeader->srcMac[3] = 0xC0;
	pEtherHeader->srcMac[4] = 0x00; pEtherHeader->srcMac[5] = 0x01;

	pEtherHeader->type = htons(0x0800);

	IpHeader* pIpHeader = (IpHeader*)(frameData + sizeof(EtherHeader));
	pIpHeader->verIhl = 0x45;
	pIpHeader->tos = 0x00;
	pIpHeader->length = htons(40);
	pIpHeader->id = 0x3412;
	pIpHeader->fragOffset = htons(0x4000); //DF
	pIpHeader->ttl = 0xFF;
	pIpHeader->protocol = 6; // TCP
	pIpHeader->checksum = 0x0000;

	pIpHeader->srcIp[0] = 192;
	pIpHeader->srcIp[1] = 168;
	pIpHeader->srcIp[2] = 41;
	pIpHeader->srcIp[3] = 1;

	pIpHeader->dstIp[0] = 192;
	pIpHeader->dstIp[1] = 168;
	pIpHeader->dstIp[2] = 41;
	pIpHeader->dstIp[3] = 128;

	int ipHeaderLen = 20;
	TcpHeader* pTcpHeader =
		(TcpHeader*)(frameData + sizeof(EtherHeader) + ipHeaderLen);

	pTcpHeader->srcPort = htons(ntohs(pTcp->srcPort)); //반드시 일치
	pTcpHeader->dstPort = htons(25000);
	pTcpHeader->seq = (pTcp->seq); // 반드시 일치 , pTcp->seq 값은 이미 Net-order 순서이므로 변환없이 그대로 복사
	pTcpHeader->ack = 0;
	pTcpHeader->data = 0x50;
	pTcpHeader->flags = 0x04; //RST
	pTcpHeader->windowSize = 0;
	pTcpHeader->checksum = 0x0000;
	pTcpHeader->urgent = 0;

	pIpHeader->checksum = CalcChecksumIp(pIpHeader);
	pTcpHeader->checksum = CalcChecksumTcp(pIpHeader, pTcpHeader);

	/* Send down the packet */
	if (pcap_sendpacket(const_cast<pcap_t*>(adhandle),	// Adapter
		frameData, // buffer with the packet
		sizeof(EtherHeader) + sizeof(IpHeader) + sizeof(TcpHeader)
	) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(const_cast<pcap_t*>(adhandle)));
	}
}
