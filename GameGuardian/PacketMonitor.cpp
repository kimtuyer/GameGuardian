#include "PacketMonitor.h"
#include "Global.h"
#include "Util.h"
#include "PacketCapture.h"
#include "PacketDetect.h"
PacketMonitor::PacketMonitor()
{
	worker_queues.resize(NUM_WORKER_THREADS);
}

PacketMonitor::~PacketMonitor()
{
}

bool PacketMonitor::Initialize()
{
	if (!DataLoader::Load("config.json", m_config)) {
		return false;
	}

	m_packetCapture = make_unique<PacketCapture>(worker_queues, blacklist_queue, m_config);
	m_packetDetect= make_unique<PacketDetect>(worker_queues, blacklist_queue, m_config);

	return true;

}

void PacketMonitor::Run()
{
	m_packetCapture.get()->Run();

}
