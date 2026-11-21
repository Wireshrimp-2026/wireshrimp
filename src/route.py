# =============================================================================
# 담당자  : B
# 맡은 기능: traceroute 홉 표 (DESIGN 7.7)
#            - UDP 방식: 프로브(OUT, 목적지 포트 33434~33534) — IP TTL이 홉 번호
#              응답 ICMP 11/0(중간 라우터) · 3/3(도착)을 ICMP 안 원본 목적지 IP·포트로 프로브와 짝짓기
#            - ICMP 방식(traceroute -I): Echo Request(8)의 id·seq ↔ Echo Reply(0) 또는 Time Exceeded 안 원본 id·seq
#            - RTT = ICMP 수신 시각 − 프로브 송신 시각, 무응답은 None
#            - 읽는 값: pkt.ip(ttl, src_ip, dst_ip), pkt.udp(dst_port), pkt.icmp, pkt.ts, pkt.direction
# 완료 기준: traceroute(UDP·ICMP 방식) 결과가 목적지별 홉 목록으로 나온다.
# =============================================================================
from __future__ import annotations

from .models import Hop, PacketInfo


class RouteTracker:
    """PacketInfo를 하나씩 받아 traceroute 프로브와 ICMP 응답을 짝짓는다."""

    def add(self, pkt: PacketInfo) -> None:
        """프로브 또는 ICMP 응답이면 기록, 아니면 무시."""
        raise NotImplementedError

    def hops(self) -> dict[str, list[Hop]]:
        """{목적지 IP: [Hop, ...]} — 홉 번호 순. traceroute가 없었으면 빈 dict."""
        raise NotImplementedError
