# =============================================================================
# 담당자  : A
# 맡은 기능: F2 계층별 해석 — Ethernet(14B), IPv4(20B~) 헤더 파싱
#            - Ethernet: 출발지·목적지 MAC, EtherType (0x0800 → IPv4)
#            - IP: 버전, 헤더 길이, TTL, Protocol(6 TCP / 17 UDP / 1 ICMP), 출발지·목적지 IP
#            - 여러 바이트 필드는 big-endian → struct "!" 형식
#            - 데이터가 짧거나 깨졌으면 ValueError
# 완료 기준: sudo 실행 시 curl http://neverssl.com 트래픽이 OUT/IN 구분되어
#            PacketInfo로 나온다. IP·TTL이 Wireshark와 일치한다.
# =============================================================================
from __future__ import annotations


def parse_ethernet(frame: bytes) -> tuple[dict, int, bytes]:
    """이더넷 프레임 → ({"src_mac", "dst_mac"}, EtherType, 나머지 bytes)."""
    raise NotImplementedError


def parse_ip(data: bytes) -> tuple[dict, bytes]:
    """IPv4 패킷 → ({"version", "ihl", "ttl", "protocol", "src_ip", "dst_ip", ...}, 나머지 bytes)."""
    raise NotImplementedError
