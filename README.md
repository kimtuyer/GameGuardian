시연영상 더미클라 3000 게임서버 대상 테스트:  https://www.youtube.com/watch?v=MssmUexTs4M
시연영상 동작방법 및 결과 (채팅서버-클라간 연결 감시 및 차단 : https://youtu.be/7_c7Zt0j-V4

주요 기능  (Key Features)
GameGuardian은 탐지, 차단, 그리고 분석에 이르는 통합 보안 프로세스를 제공합니다.

① 지능형 3단계 패킷 필터링 (Multi-Layer Defense)
Blacklist: 위협이 확정된 IP를 즉시 차단합니다.
비상모드: 초당 전체 패킷유입 수가 임계값 초과시 SYN/ACK 비율을 모니터링 하여, 비상모드가 발동되어 아래의 패킷 필터링을 실시합니다.
Greylist (First Packet Drop): 처음 접속하는 모든 SYN 패킷을 의도적으로 드랍하여, 재전송을 시도하지 않는 가짜 IP(Spoofing) 공격을 1차 선별합니다.
Whitelist (Dynamic Verification): 정상적인 재전송을 마친 클라이언트를 승격시키며, 승격 후에도 SYN/ACK 비율을 지속 모니터링하여 고정 IP 기반의 변칙 공격을 실시간 감시합니다.

② TCP 상태 가상화 및 강제 연결 해제 (RST Packet Injection)
커널 레이어 모방: 캡처한 패킷의 Sequence/Acknowledgment Number를 역추적하여 운영체제가 생성하는 것과 동일한 구조의 RST(Reset) 패킷을 로우 소켓으로 직접 생성합니다.
공격 차단: 공격자에게 RST 패킷을 송신하여 서버의 백로그 큐(Backlog Queue) 점유를 즉각 해제하고 자원을 보호합니다.

③ 로컬 AI 기반 지능형 관제 (AIOps)
실시간 로그 요약: 초당 수천 건의 보안 로그를 로컬 LLM(Qwen2.5:14b)이 분석하여 핵심 위협 상황을 도출합니다.
스마트 리포팅: 분석된 결과(공격 유형, 위험도, 대응 제안)를 텔레그램으로 전송하여 관리자의 판단을 돕습니다.
시연영상 첨부: https://youtu.be/XQZlEbpREpM
