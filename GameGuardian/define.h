#pragma once
#include <pcap.h>
#include <thread>
#include <vector>
#include <concurrent_queue.h>
#include<map>
#include<string>
#include<chrono>
#include<mutex>
#include<Windows.h>
#include <queue>
#include <set>
#include <tchar.h>
#include <WinSock2.h>
#include <time.h>
#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")
#define __VER2__
#define __OOP__
#define __DATA_LOADING__
using namespace std;

const int NUM_WORKER_THREADS = 8;
const int TIME_WAIT = 1000;

#pragma pack(push, 1)
typedef struct EtherHeader {
	unsigned char dstMac[6];
	unsigned char srcMac[6];
	unsigned short type;
} EtherHeader;

typedef struct IpHeader {
	unsigned char verIhl;
	unsigned char tos;
	unsigned short length;
	unsigned short id;
	unsigned short fragOffset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned char srcIp[4];
	unsigned char dstIp[4];
} IpHeader;

typedef struct TcpHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned int seq;
	unsigned int ack;
	unsigned char data;
	unsigned char flags;
	unsigned short windowSize;
	unsigned short checksum;
	unsigned short urgent;
} TcpHeader;

typedef struct UdpHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned short length;
	unsigned short checksum;
} UdpHeader;

typedef struct PseudoHeader {
	unsigned int srcIp;
	unsigned int dstIp;
	unsigned char zero;
	unsigned char protocol;
	unsigned short length;
} PseudoHeader;

typedef struct Packet {

	struct pcap_pkthdr m_pheader {};
	vector<u_char> m_pkt_data;
	Packet()
	{

	}

	Packet(struct pcap_pkthdr* header, u_char* pkt_data)
	{
		if (header != nullptr && pkt_data != nullptr) {
			// 헤더 복사 (구조체끼리 대입하면 값 복사됨)
			m_pheader = *header;

			// [핵심] 데이터 깊은 복사 (Deep Copy)
			// vector의 assign 함수: 시작 포인터부터 길이만큼 복사해서 내 메모리에 저장
			m_pkt_data.assign(pkt_data, pkt_data + header->caplen);
		}
		//m_pheader = header;
		//m_pkt_data = pkt_data;
	}

};
// 생산자(Producer)가 패킷 처리에 필요한 모든 '상태'를 담는 가방
struct CaptureContext {
	// 로컬 블랙리스트 (락 필요 없음, 생산자만 봄)
	set<uint32_t> local_blacklist;
	// 워커들에게서 차단 요청을 받을 피드백 큐 (스레드 안전)
	//concurrency::concurrent_queue<uint32_t> feedback_queue;
};
#pragma pack(pop)