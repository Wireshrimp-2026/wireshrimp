# =============================================================================
# 담당자  : A
# 맡은 기능: F2 계층별 해석 — decode(): 계층 파서 합치기
#            - parse_ethernet → parse_ip → parse_tcp/udp(B)·parse_icmp(D) → parse_dns/http(C) 순서로 호출
#            - IPv4가 아니면 None
#            - 하위 파서의 예외(ValueError 등)는 잡아서 해당 부분만 None으로 두고 계속 진행
# 완료 기준: sudo 실행 시 curl http://neverssl.com 트래픽이 OUT/IN 구분되어
#            PacketInfo로 나온다. IP·TTL이 Wireshark와 일치한다.
#            실험 스크립트로 조건별 반복 실행 시 CSV가 쌓인다.
# =============================================================================
from __future__ import annotations

from typing import Optional

from ..models import Captured, PacketInfo
from .app_dns import parse_dns
from .app_http import parse_http
from .icmp import parse_icmp
from .link_ip import parse_ethernet, parse_ip
from .transport import parse_tcp, parse_udp

__all__ = [
    "decode",
    "parse_ethernet", "parse_ip",      # A
    "parse_tcp", "parse_udp",          # B
    "parse_icmp",                      # D
    "parse_dns", "parse_http",         # C
]


def decode(captured: Captured) -> Optional[PacketInfo]:
    """Captured → PacketInfo, 해석 대상이 아니면(IPv4 아님 등) None."""
    raise NotImplementedError
