#include "PacketCapture.h"
//#include "Global.h"

PacketCapture::PacketCapture(std::vector<map<uint32_t, pair<Packet, int>>>&worker_queues, concurrency::concurrent_queue<uint32_t>&blacklist_queue,
	const NetworkConfig& config)
	:m_pWorker_queues(worker_queues),m_pBlacklist_queue(blacklist_queue), m_config(config)
{

}
PacketCapture::~PacketCapture()
{
}

void PacketCapture::packet_capture(const pcap_pkthdr* header, const u_char* pkt_data)
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

	while (m_pBlacklist_queue.try_pop(ip))
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
		if (m_pWorker_queues[worker_index].contains(src_ip))
		{
			//클라->서버 ,서버->클라, 클라->서버 ACK 보내는 마지막 패킷 캡쳐
			if (pTcp->flags == 0x010) // Flags 비트 값이 0x010 (ACK)일 경우에만 패킷데이터 업데이트!
			{
				m_pWorker_queues[worker_index][src_ip].first = data;
				m_pWorker_queues[worker_index][src_ip].second++;
			}
			else
			{
				// Flags 비트 값이 0x010 (ACK) 가 아닐 경우엔 카운트만 증가
				m_pWorker_queues[worker_index][src_ip].second++;
			}
		}
		else
		{
			m_pWorker_queues[worker_index].insert({ src_ip ,{data,1} });
		}
	}
}

void PacketCapture::packet_handler(u_char* user, const pcap_pkthdr* header, const u_char* pkt_data)
{
	// user로 들어온 포인터를 PacketMonitor 클래스 포인터로 캐스팅
	PacketCapture* self = reinterpret_cast<PacketCapture*>(user);

	// 실제 멤버 함수 호출
	self->packet_capture(header, pkt_data);
}

void PacketCapture::Run()
{
	pcap_loop(const_cast<pcap_t*>(PcapAdmin.GetHandle()), 0, packet_handler, (u_char*)this);

}
