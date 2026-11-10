# =============================================================================
# 담당자  : B
# 맡은 기능: F3 접속 단위로 묶기
#            1. DNS 응답에서 도메인 → IP 짝 저장
#            2. 그 IP로 향하는 SYN → 새 TCP 연결 (내 IP, 내 포트, 서버 IP, 서버 포트)
#            3. 같은 4개 묶음의 HTTP 요청·응답, FIN을 같은 접속에 붙이기
#            (traceroute 경로는 route.py — D, route_probes는 main.py가 채움)
# 완료 기준: Seq/Ack/Flags, UDP 포트·Length가 Wireshark와 일치한다. 접속 1회가 Session 1개로
#            묶이고, SYN·SYN/ACK·ACK·HTTP 요청·응답·FIN이 모두 붙는다.
# =============================================================================
from __future__ import annotations

from .models import PacketInfo, Session


class SessionBuilder:
    """PacketInfo를 하나씩 받아 웹 접속 단위(Session)로 묶는다."""

    def add(self, pkt: PacketInfo) -> None:
        """패킷 1건을 받아 알맞은 접속에 붙인다."""
        raise NotImplementedError

    def sessions(self) -> list[Session]:
        """지금까지 묶인 Session 목록."""
        raise NotImplementedError
