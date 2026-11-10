# =============================================================================
# 담당자  : D
# 맡은 기능: F2 계층별 해석 — ICMP 파싱
#            - Type, Code (11 → Time Exceeded, 3 → 도착/Port Unreachable)
#            - ICMP 안에 담긴 원본 IP 헤더의 목적지 IP, 원본 UDP 헤더의 목적지 포트
#            - 데이터가 짧거나 깨졌으면 ValueError
# 완료 기준: ICMP Type·Code·원본 목적지 IP·포트가 Wireshark와 일치한다. traceroute 프로브와
#            ICMP 응답이 짝지어져 홉별 지연이 계산된다. 설계안 출력 예시 모양의 타임라인이
#            찍히고 CSV가 2.6 형식으로 쌓인다.
# =============================================================================
from __future__ import annotations


def parse_icmp(data: bytes) -> tuple[dict, bytes]:
    """ICMP 메시지 → ({"icmp_type", "icmp_code", "icmp_orig_dst_ip", "icmp_orig_dst_port"}, 나머지 bytes)."""
    raise NotImplementedError
