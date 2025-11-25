#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <thread>
#include <vector>
#include <concurrent_queue.h>
#include<Windows.h>
#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")

#include <tchar.h>
#include <WinSock2.h>

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

	struct pcap_pkthdr* m_pheader;
	u_char* m_pkt_data;
	Packet() :m_pheader(nullptr), m_pkt_data(nullptr)
	{

	}

	Packet(struct pcap_pkthdr* header, u_char* pkt_data)
	{
		m_pheader = header;
		m_pkt_data = pkt_data;
	}

};
#pragma pack(pop)



using namespace std;
vector<char*> Payloadlist;
//vector<char*> PacketBuffer;
vector<Packet>local_buffer;
Concurrency::concurrent_queue<Packet> PacketBuffer;
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}

	return TRUE;
}

unsigned short CalcChecksumIp(IpHeader* pIpHeader)
{
	unsigned char ihl = (pIpHeader->verIhl & 0x0F) << 2; //*4와 동일
	unsigned short wData[30] = { 0 };
	unsigned int dwSum = 0;

	memcpy(wData, (BYTE*)pIpHeader, ihl);
	//((IpHeader*)wData)->checksum = 0x0000;

	for (int i = 0; i < ihl / 2; i++)
	{
		if (i != 5)
			dwSum += wData[i];

		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	return ~(dwSum & 0x0000FFFF);
}

unsigned short CalcChecksumTcp(IpHeader* pIpHeader, TcpHeader* pTcpHeader)
{
	PseudoHeader	pseudoHeader = { 0 };
	unsigned short* pwPseudoHeader = (unsigned short*)&pseudoHeader;
	unsigned short* pwDatagram = (unsigned short*)pTcpHeader;
	int				nPseudoHeaderSize = 6; //WORD 6개 배열
	int				nSegmentSize = 0; //헤더 포함

	UINT32			dwSum = 0;
	int				nLengthOfArray = 0;

	pseudoHeader.srcIp = *(unsigned int*)pIpHeader->srcIp;
	pseudoHeader.dstIp = *(unsigned int*)pIpHeader->dstIp;
	pseudoHeader.zero = 0;
	pseudoHeader.protocol = 6;
	pseudoHeader.length = htons(ntohs(pIpHeader->length) - 20);


	nSegmentSize = ntohs(pseudoHeader.length);

	if (nSegmentSize % 2)
		nLengthOfArray = nSegmentSize / 2 + 1;
	else
		nLengthOfArray = nSegmentSize / 2;

	for (int i = 0; i < nPseudoHeaderSize; i++)
	{
		dwSum += pwPseudoHeader[i];
		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	for (int i = 0; i < nLengthOfArray; i++)
	{
		if (i != 8)
			dwSum += pwDatagram[i];
		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	return (USHORT)~(dwSum & 0x0000FFFF);
}

void packet_Reset(pcap_t* adhandle)
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

	pTcpHeader->srcPort = htons(8011); //반드시 일치
	pTcpHeader->dstPort = htons(25000);
	pTcpHeader->seq = htonl(0x005f062f); //반드시 일치
	pTcpHeader->ack = 0;
	pTcpHeader->data = 0x50;
	pTcpHeader->flags = 0x04; //RST
	pTcpHeader->windowSize = 0;
	pTcpHeader->checksum = 0x0000;
	pTcpHeader->urgent = 0;


	pIpHeader->checksum = CalcChecksumIp(pIpHeader);
	pTcpHeader->checksum = CalcChecksumTcp(pIpHeader, pTcpHeader);

	/* Send down the packet */
	if (pcap_sendpacket(adhandle,	// Adapter
		frameData, // buffer with the packet
		sizeof(EtherHeader) + sizeof(IpHeader) + sizeof(TcpHeader)
	) != 0)
	{
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(adhandle));
	}

	pcap_close(adhandle);


}

void packet_detect(pcap_t* adhandle)
{


	int size = 500;
	while (1)
	{
		Packet packet;
		if (PacketBuffer.try_pop(packet) == false)
			Sleep(1);
		else
		{
			/*



			*/
			if (packet.m_pkt_data == nullptr || packet.m_pheader == nullptr)
				return;

			EtherHeader* pEther = (EtherHeader*)packet.m_pkt_data;
			IpHeader* pIpHeader = (IpHeader*)(packet.m_pkt_data + sizeof(EtherHeader));

			/*if (pEther->type != 0x0008)
				return;

			if (pIpHeader->protocol != 6)
				return;*/

			int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
			TcpHeader* pTcp =
				(TcpHeader*)(packet.m_pkt_data + sizeof(EtherHeader) + ipHeaderLen);

			/*	if (ntohs(pTcp->srcPort) != 25000 &&
					ntohs(pTcp->dstPort) != 25000)
					return;*/

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

			printf("Segment size: %d(Frame length: %d)\n",
				ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize,
				packet.m_pheader->len);

			/*char szMessage[2048] = { 0 };
			memcpy_s(szMessage, sizeof(szMessage), pPayload,
				ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize);
			puts(szMessage);*/

			packet_Reset(adhandle);

			/*char szMessage[2048] = { 0 };
			memcpy_s(szMessage, sizeof(szMessage), pPayload,
				ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize);
			puts(szMessage);*/

		}

	}

}

void packet_handler(u_char* temp1,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data)
{
	EtherHeader* pEther = (EtherHeader*)pkt_data;
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	if (pEther->type != 0x0008)
		return;

	if (pIpHeader->protocol != 6)
		return;

	int ipHeaderLen = (pIpHeader->verIhl & 0x0F) * 4;
	TcpHeader* pTcp =
		(TcpHeader*)(pkt_data + sizeof(EtherHeader) + ipHeaderLen);

	//일단 내 포트폴리오 게임서버 포트로 설정 ,클라는 각각 당연히 포트가 다를것.
	if (ntohs(pTcp->dstPort) != 25000) //ntohs(pTcp->srcPort) != 25000 &&
		return;


	Packet data(const_cast<pcap_pkthdr*>(header), const_cast<u_char*>(pkt_data));

	/*printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
		pIpHeader->srcIp[0], pIpHeader->srcIp[1],
		pIpHeader->srcIp[2], pIpHeader->srcIp[3],
		ntohs(pTcp->srcPort),
		pIpHeader->dstIp[0], pIpHeader->dstIp[1],
		pIpHeader->dstIp[2], pIpHeader->dstIp[3],
		ntohs(pTcp->dstPort)
	);

	int tcpHeaderSize = ((pTcp->data >> 4 & 0x0F) * 4);
	char* pPayload = (char*)(pkt_data + sizeof(EtherHeader) +
		ipHeaderLen + tcpHeaderSize);

	printf("Segment size: %d(Frame length: %d)\n",
		ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize,
		header->len);*/

	if (local_buffer.size() < 500)
		local_buffer.push_back(data);

	for (auto data : local_buffer)
		PacketBuffer.push(data);
	local_buffer.clear();

	/*char szMessage[2048] = { 0 };
	memcpy_s(szMessage, sizeof(szMessage), pPayload,
		ntohs(pIpHeader->length) - ipHeaderLen - tcpHeaderSize);
	puts(szMessage);*/
}

int main()
{
	pcap_if_t* alldevs{};
	pcap_if_t* d{};
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	Payloadlist.reserve(1000);

	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}


	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	/* Open the adapter */



	//if ((adhandle = pcap_open_live(d->name,	// name of the device
	//	65536,			// portion of the packet to capture. 
	//	// 65536 grants that the whole packet will be captured on all the MACs.
	//	1,				// promiscuous mode (nonzero means promiscuous)
	//	1,			// read timeout , defaut= 1000
	//	errbuf			// error buffer
	//)) == NULL)
	//{
	//	fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
	//	/* Free the device list */
	//	pcap_freealldevs(alldevs);
	//	return -1;
	//}
	/* 1. pcap_open_live 대신 pcap_create로 핸들을 생성합니다. */
	if ((adhandle = pcap_create(d->name, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to create the adapter handle. %s\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}
	// pcap 핸들 생성 후 활성화 전에 설정
	if (pcap_set_buffer_size(adhandle, 64 * 1024 * 1024) != 0) {
		fprintf(stderr, "Warning: Failed to set buffer size.\n");
	} // 64MB로 설정

	/* 3. 필요한 다른 설정을 합니다. */
	pcap_set_snaplen(adhandle, 65536); // 캡처할 패킷 부분 (스냅 길이)
	pcap_set_promisc(adhandle, 1);     // 무차별 모드
	pcap_set_timeout(adhandle, 1);     // 읽기 타임아웃 (1ms)


	/* 4. pcap_activate로 디바이스를 활성화합니다. */
	int activate_status = pcap_activate(adhandle);
	if (activate_status != 0) {
		// 활성화 실패 처리 (activate_status 값에 따라 에러 타입 확인 가능)
		fprintf(stderr, "\nUnable to activate the adapter. %s: %s\n", d->name, pcap_geterr(adhandle));
		pcap_close(adhandle);
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);



	// 커널 버퍼에 최소 16KB가 쌓일 때까지 리턴하지 않음 (Context Switching 감소)
	if (pcap_setmintocopy(adhandle, 16 * 1024) != 0) {
		fprintf(stderr, "Warning: pcap_setmintocopy failed.\n");
	}	/* start the capture */

	////캡쳐한 패킷 버퍼에서 뽑아내 추출하는 스레드풀 생성
	const int threadCnt = std::thread::hardware_concurrency();
	std::vector<thread> ThreadPool;
	for (int i = 0; i < threadCnt; i++)
		ThreadPool.push_back(thread(packet_detect, adhandle));


	pcap_loop(adhandle, 0, packet_handler, NULL);



	for (int i = 0; i < threadCnt; i++)
		if (ThreadPool[i].joinable())
			ThreadPool[i].join();

	pcap_close(adhandle);

	return 0;
}
