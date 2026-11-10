# =============================================================================
# 담당자  : D
# 맡은 기능: 경로(traceroute) 추적
#            - traceroute UDP 프로브(OUT, 목적지 포트 33434~)를 목적지 서버 IP별로 모으기
#            - ICMP 응답(Type 11 Time Exceeded / Type 3 도착)을 ICMP 안 원본 UDP 목적지 포트로
#              프로브와 짝짓기 (응답 없으면 None)
#            - 홉별 지연: 프로브(OUT) → ICMP 응답(IN), 무응답은 None
# 완료 기준: ICMP Type·Code·원본 목적지 IP·포트가 Wireshark와 일치한다. traceroute 프로브와
#            ICMP 응답이 짝지어져 홉별 지연이 계산된다. 설계안 출력 예시 모양의 타임라인이
#            찍히고 CSV가 2.6 형식으로 쌓인다.
# =============================================================================
from __future__ import annotations

from typing import Optional

from .models import Hop, PacketInfo


class RouteTracker:
    """PacketInfo를 하나씩 받아 traceroute 프로브와 ICMP 응답을 짝짓는다."""

    def add(self, pkt: PacketInfo) -> None:
        """패킷 1건을 받아 프로브 또는 ICMP 응답이면 기록한다."""
        raise NotImplementedError

    def probes_for(self, server_ip: str) -> list[tuple[PacketInfo, Optional[PacketInfo]]]:
        """server_ip로 보낸 프로브 목록 → [(프로브, 짝지은 ICMP 응답 또는 None), ...] (시간순)."""
        raise NotImplementedError


def hop_delays(probes: list[tuple[PacketInfo, Optional[PacketInfo]]]) -> list[Hop]:
    """(프로브, 응답) 목록 → [(홉 번호, 라우터 IP, 지연 ms), ...] — 무응답은 (n, None, None)."""
    raise NotImplementedError
