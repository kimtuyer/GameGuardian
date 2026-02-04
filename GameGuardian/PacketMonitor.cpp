#include "PacketMonitor.h"
#include "Global.h"
#include "Util.h"
#include "PacketCapture.h"
#include "PacketDetect.h"
#include "CLogManager.h"

PacketMonitor::PacketMonitor(const NetworkConfig& config)
{
	//worker_queues.resize(NUM_WORKER_THREADS);
	CLogManager::GetInstance().SetLogFilePath("C:/Users/kimtu/source/repos/GameGuardian/logs/GameGuard_Log.txt");

	m_context = make_unique<SharedContext>(config);

	m_packetCapture = make_unique<PacketCapture>(*m_context);
	m_packetDetect = make_unique<PacketDetect>(*m_context);
}

PacketMonitor::~PacketMonitor()
{
}

bool PacketMonitor::Initialize()
{
	/*if (!DataLoader::Load("config.json", m_config)) {
		printf("Can not Loading Config.json!");
		return false;
	}*/

	/*m_packetCapture = make_unique<PacketCapture>(worker_queues, blacklist_queue, m_config);
	m_packetDetect= make_unique<PacketDetect>(worker_queues, blacklist_queue, m_config);*/

	return true;

}

void PacketMonitor::Run()
{
	CLogManager::GetInstance().Log("Guard_Start!");

	m_packetCapture.get()->Run();

}
