# =============================================================================
# 담당자  : B
# 맡은 기능: ICMP 해석 (DESIGN 7.7)
#            - Type, Code, Checksum, type_name
#            - Echo Request(8) / Reply(0): Identifier, Sequence
#            - Time Exceeded(11) / Destination Unreachable(3): 안에 담긴 원본 IP 헤더 + 앞 8바이트
#              → orig_src_ip, orig_dst_ip, orig_proto, orig_ttl, (UDP면) orig_src_port, orig_dst_port,
#                (ICMP Echo면) orig_id, orig_seq
#            - 데이터가 짧거나 깨졌으면 ValueError
# 완료 기준: ICMP Type·Code와 안쪽 원본 IP·포트가 PacketInfo.icmp에 담긴다.
# =============================================================================
from __future__ import annotations


def parse_icmp(data: bytes) -> dict:
    """ICMP 메시지 → 필드 dict (키는 models.PacketInfo.icmp 주석 참고)."""
    raise NotImplementedError
