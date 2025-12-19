#include "PacketMonitor.h"
#include "Global.h"
#include "Util.h"
PacketMonitor::PacketMonitor()
{
	worker_queues.resize(NUM_WORKER_THREADS);

	for (int i = 0; i < NUM_WORKER_THREADS; i++)
		ThreadPool.push_back(thread(&PacketMonitor::packet_detect, this, i, PcapAdmin.GetHandle()));

	pcap_loop(const_cast<pcap_t*>(PcapAdmin.GetHandle()), 0, packet_handler, (u_char*)this);
}

PacketMonitor::~PacketMonitor()
{
	for (int i = 0; i < NUM_WORKER_THREADS; i++)
		if (ThreadPool[i].joinable())
			ThreadPool[i].join();
}

void PacketMonitor::packet_capture(const pcap_pkthdr* header, const u_char* pkt_data)
{
	//CaptureContext* ctx = (CaptureContext*)param;
	EtherHeader* pEther = (EtherHeader*)pkt_data;
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	uint32_t src_ip = *(uint32_t*)(pIpHeader->srcIp);
	uint32_t ip{};

	int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
	TcpHeader* pTcp = (TcpHeader*)(pkt_data + sizeof(EtherHeader) + ipHeaderLen);

	//이미 차단된 계정이 다시 접속을 시도할경우? 도 생각해서 차단해야함!
	if (local_blacklist.contains(src_ip))
	{
		//차단된 계정이 다시 접속을 시도해 연결 수립하는 ack 패킷은 다시 캡쳐 후 탐지해서 차단!
		if (pTcp->flags != 0x010)
			return;
	}
	auto now = std::chrono::steady_clock::now();

	while (blacklist_queue.try_pop(ip))
	{
		auto last_check_time = std::chrono::steady_clock::now();

		//1초이상 경과시 다음에 처리
		if (chrono::duration_cast<std::chrono::seconds>(now - last_check_time).count() >= 1)
		{
			break;
		}

		local_blacklist.insert(ip);
	}

	if (pEther->type != 0x0008)
		return;

	if (pIpHeader->protocol != 6)
		return;

	if (pTcp->flags == 0x004) //RST 패킷, 즉 툴이 보내는 종료패킷은 제외!
		return;

	//if (pIpHeader->id == 0x3412)
	//	return; //툴 자신이 생성해 보낸 패킷은 제외!

	//일단 내 포트폴리오 게임서버 포트로 설정 ,클라는 각각 당연히 포트가 다를것.
	if (ntohs(pTcp->srcPort) != 25000 && ntohs(pTcp->dstPort) != 25000) //ntohs(pTcp->srcPort) != 25000 &&
		return;

	Packet data(const_cast<pcap_pkthdr*>(header), const_cast<u_char*>(pkt_data));

	int worker_index = src_ip % NUM_WORKER_THREADS;

	{
		std::lock_guard<mutex> lock(m1[worker_index]);
		if (worker_queues[worker_index].contains(src_ip))
		{
			//클라->서버 ,서버->클라, 클라->서버 ACK 보내는 마지막 패킷 캡쳐
			if (pTcp->flags == 0x010) // Flags 비트 값이 0x010 (ACK)일 경우에만 패킷데이터 업데이트!
			{
				worker_queues[worker_index][src_ip].first = data;
				worker_queues[worker_index][src_ip].second++;
			}
			else
			{
				// Flags 비트 값이 0x010 (ACK) 가 아닐 경우엔 카운트만 증가
				worker_queues[worker_index][src_ip].second++;
			}
		}
		else
		{
			worker_queues[worker_index].insert({ src_ip ,{data,1} });
		}
	}
}

void PacketMonitor::packet_handler(u_char* user, const pcap_pkthdr* header, const u_char* pkt_data)
{
	// user로 들어온 포인터를 PacketMonitor 클래스 포인터로 캐스팅
	PacketMonitor* self = reinterpret_cast<PacketMonitor*>(user);

	// 실제 멤버 함수 호출
	self->packet_capture(header, pkt_data);
}

void PacketMonitor::packet_detect(const int ThreadID, const pcap_t* adhandle)
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

		for (auto[ip,data]:local_IPList)
		{
			accomulate_stat[ip].second += data.second;

			auto packet = data.first;

			if (packet.m_pkt_data == nullptr || packet.m_pheader == nullptr)
				continue;

			accomulate_stat[ip].first = packet;


			EtherHeader* pEther = (EtherHeader*)packet.m_pkt_data;
			IpHeader* pIpHeader = (IpHeader*)(packet.m_pkt_data + sizeof(EtherHeader));

			int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
			TcpHeader* pTcp =
				(TcpHeader*)(packet.m_pkt_data + sizeof(EtherHeader) + ipHeaderLen);

			printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
				pIpHeader->srcIp[0], pIpHeader->srcIp[1],
				pIpHeader->srcIp[2], pIpHeader->srcIp[3],
				ntohs(pTcp->srcPort),
				pIpHeader->dstIp[0], pIpHeader->dstIp[1],
				pIpHeader->dstIp[2], pIpHeader->dstIp[3],
				ntohs(pTcp->dstPort)
			);

			int tcpHeaderSize = ((pTcp->data >> 4 & 0x0F) * 4);
			char* pPayload = (char*)(packet.m_pkt_data + sizeof(EtherHeader) +
				ipHeaderLen + tcpHeaderSize);

			int Segmentsize = ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize;
			printf("Segment size: %d(Frame length: %d)\n",
				Segmentsize,
				packet.m_pheader->len);


			if (accomulate_stat[ip].second < 100)
				continue;
	
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

void PacketMonitor::packet_Reset(const TcpHeader* pTcp, const pcap_t* adhandle)
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