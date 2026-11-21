# =============================================================================
# 담당자  : A
# 맡은 기능: F2 계층별 해석 — TCP, UDP 헤더 파싱 (DESIGN 7.2)
#            - TCP: Source Port, Destination Port, Sequence No, Acknowledgement No, Data Offset,
#              Flags 9비트("ACK,SYN" 형식, 순서는 models.TCP_FLAG_ORDER), Window, Checksum,
#              Urgent Pointer, Options(MSS, Window Scale, SACK Permitted, SACK, Timestamps, NOP, EOL)
#            - UDP: Source Port, Destination Port, Length, Checksum
#            - UDP 체크섬은 반드시 검증한다 (checksum_ok):
#              의사 헤더(출발지 IP 4B, 목적지 IP 4B, 0 1B, Protocol 17 1B, UDP Length 2B)
#              + UDP 헤더(체크섬 칸 그대로) + 데이터를 16비트 1의 보수로 더해 0이면 True, 아니면 False
#              체크섬 값이 0이면 송신 측이 쓰지 않은 것(IPv4에서 허용) → None
#              (1의 보수 합은 link_ip.ip_checksum()을 그대로 쓰면 된다)
#            - 데이터가 짧거나 깨졌으면 ValueError
# 완료 기준: TCP 전 필드(옵션 포함)와 UDP 전 필드·체크섬 검증 결과가 PacketInfo.tcp / .udp에 담긴다.
# =============================================================================
from __future__ import annotations


def parse_tcp(data: bytes) -> tuple[dict, bytes]:
    """TCP 세그먼트 → (필드 dict, 페이로드 bytes).

    dict 키: src_port, dst_port, seq, ack, header_len, flags(str), flag_bits(int),
             window, checksum, urgent, options(list[str], 예: ["MSS=1460", "NOP", "WS=7"])
    """
    raise NotImplementedError


def parse_udp(data: bytes, src_ip: str, dst_ip: str) -> tuple[dict, bytes]:
    """UDP 데이터그램 → (필드 dict, 페이로드 bytes).

    src_ip, dst_ip: 의사 헤더를 만들 IP 주소 ("10.0.2.15" 형식)
    dict 키: src_port, dst_port, length, checksum, checksum_ok(True / False / None=체크섬 안 씀)
    """
    raise NotImplementedError
