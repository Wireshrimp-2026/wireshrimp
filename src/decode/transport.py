# =============================================================================
# 담당자  : B
# 맡은 기능: F2 계층별 해석 — TCP, UDP 헤더 파싱
#            - TCP: 포트, Seq, Ack, 헤더 길이, Flags("SYN,ACK" 형식, 순서 SYN,FIN,RST,PSH,ACK), Window
#            - UDP: 포트, Length
#            - 데이터가 짧거나 깨졌으면 ValueError
#            (ICMP는 decode/icmp.py — D)
# 완료 기준: Seq/Ack/Flags, UDP 포트·Length가 Wireshark와 일치한다. 접속 1회가 Session 1개로
#            묶이고, SYN·SYN/ACK·ACK·HTTP 요청·응답·FIN이 모두 붙는다.
# =============================================================================
from __future__ import annotations


def parse_tcp(data: bytes) -> tuple[dict, bytes]:
    """TCP 세그먼트 → ({"src_port", "dst_port", "seq", "ack", "tcp_flags", "window", ...}, 페이로드 bytes)."""
    raise NotImplementedError


def parse_udp(data: bytes) -> tuple[dict, bytes]:
    """UDP 데이터그램 → ({"src_port", "dst_port", "udp_length"}, 페이로드 bytes)."""
    raise NotImplementedError
