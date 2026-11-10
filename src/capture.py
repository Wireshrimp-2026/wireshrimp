# =============================================================================
# 담당자  : A
# 맡은 기능: F1 캡처
#            - socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))로 모든 프레임 수신 (root)
#            - recvfrom() 주소 정보의 pkttype == PACKET_OUTGOING(4) → "OUT", 그 외 → "IN"
#            - 받은 시각(time.time()) 기록
#            - 대상 서버 IP, 포트(53, 80), ICMP, traceroute 포트만 남기는 필터
# 완료 기준: sudo 실행 시 curl http://neverssl.com 트래픽이 OUT/IN 구분되어
#            PacketInfo로 나온다. IP·TTL이 Wireshark와 일치한다.
#            실험 스크립트로 조건별 반복 실행 시 CSV가 쌓인다.
# =============================================================================
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from .models import Captured


@dataclass
class CaptureFilter:
    """캡처할 트래픽 조건."""
    server_ips: list[str] = field(default_factory=list)   # 대상 서버 IP 목록 (비어 있으면 IP로 거르지 않음)
    ports: tuple[int, ...] = (53, 80)                      # 남길 TCP/UDP 포트
    allow_icmp: bool = True                                # ICMP 허용 여부
    traceroute_ports: tuple[int, int] = (33434, 33534)     # traceroute UDP 프로브 포트 범위 (이상, 이하)


def capture(filter: CaptureFilter) -> Iterator[Captured]:
    """필터에 맞는 프레임을 받을 때마다 Captured를 하나씩 내보내는 제너레이터."""
    raise NotImplementedError
