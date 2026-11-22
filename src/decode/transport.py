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
#              데이터가 Length보다 짧게 잡혀(IP 조각 등) 검증할 수 없을 때도 → None
#              틀렸는데 체크섬 칸이 의사 헤더 합과 같으면 "랜카드가 나중에 채울 미완성 값"
#              (checksum offload) → checksum_partial=True. 출력에서 bad가 아니라 offload로 표시
#            - 데이터가 짧거나 깨졌으면 ValueError
# 완료 기준: TCP 전 필드(옵션 포함)와 UDP 전 필드·체크섬 검증 결과가 PacketInfo.tcp / .udp에 담긴다.
# =============================================================================
from __future__ import annotations

import socket
import struct
from typing import Optional

from ..models import TCP_FLAG_ORDER
from .link_ip import ip_checksum

TCP_MIN_HEADER_LEN = 20
UDP_HEADER_LEN = 8
IP_PROTO_UDP = 17

# 플래그 이름 → 비트 (NS는 Data Offset 바이트의 맨 아래 비트 → 0x100)
TCP_FLAG_BITS = {
    "FIN": 0x001, "SYN": 0x002, "RST": 0x004, "PSH": 0x008,
    "ACK": 0x010, "URG": 0x020, "ECE": 0x040, "CWR": 0x080, "NS": 0x100,
}


def flags_to_str(bits: int) -> str:
    """플래그 비트 → "ACK,SYN" (TCP_FLAG_ORDER 순서, 켜진 것만). 하나도 없으면 ""."""
    return ",".join(name for name in TCP_FLAG_ORDER if bits & TCP_FLAG_BITS[name])


def parse_tcp(data: bytes) -> tuple[dict, bytes]:
    """TCP 세그먼트 → (필드 dict, 페이로드 bytes).

    dict 키: src_port, dst_port, seq, ack, header_len, flags(str), flag_bits(int),
             window, checksum, urgent, options(list[str], 예: ["MSS=1460", "NOP", "WS=7"])
    """
    if len(data) < TCP_MIN_HEADER_LEN:
        raise ValueError(f"TCP header too short: {len(data)} bytes")
    (sport, dport, seq, ack, off_byte, flag_byte,
     window, checksum, urgent) = struct.unpack("!HHIIBBHHH", data[:TCP_MIN_HEADER_LEN])

    header_len = (off_byte >> 4) * 4
    if header_len < TCP_MIN_HEADER_LEN:
        raise ValueError(f"bad TCP data offset: {header_len}")
    if len(data) < header_len:
        raise ValueError(f"TCP options truncated: need {header_len}, got {len(data)}")

    flag_bits = ((off_byte & 0x01) << 8) | flag_byte
    info = {
        "src_port": sport,
        "dst_port": dport,
        "seq": seq,
        "ack": ack,
        "header_len": header_len,
        "flags": flags_to_str(flag_bits),
        "flag_bits": flag_bits,
        "window": window,
        "checksum": checksum,
        "urgent": urgent,
        "options": parse_tcp_options(data[TCP_MIN_HEADER_LEN:header_len]),
    }
    return info, data[header_len:]


def parse_tcp_options(raw: bytes) -> list[str]:
    """TCP 옵션 bytes → ["MSS=1460", "SACK_PERM", "TS val=1 ecr=0", "NOP", "WS=7"].

    옵션이 깨져 있으면 거기까지만 해석하고 "BAD_OPTION"을 덧붙인다 (헤더 전체를 버리지 않음).
    """
    out: list[str] = []
    i = 0
    while i < len(raw):
        kind = raw[i]
        if kind == 0:                       # End of Option List
            out.append("EOL")
            break
        if kind == 1:                       # No-Operation
            out.append("NOP")
            i += 1
            continue
        if i + 1 >= len(raw) or raw[i + 1] < 2 or i + raw[i + 1] > len(raw):
            out.append("BAD_OPTION")
            break
        length = raw[i + 1]
        body = raw[i + 2:i + length]
        if kind == 2 and length == 4:
            out.append(f"MSS={struct.unpack('!H', body)[0]}")
        elif kind == 3 and length == 3:
            out.append(f"WS={body[0]}")
        elif kind == 4 and length == 2:
            out.append("SACK_PERM")
        elif kind == 5 and length >= 10 and (length - 2) % 8 == 0:
            edges = struct.unpack(f"!{(length - 2) // 4}I", body)
            blocks = ",".join(f"{edges[j]}-{edges[j + 1]}" for j in range(0, len(edges), 2))
            out.append(f"SACK={blocks}")
        elif kind == 8 and length == 10:
            val, ecr = struct.unpack("!II", body)
            out.append(f"TS val={val} ecr={ecr}")
        else:
            out.append(f"OPT{kind} len={length}")
        i += length
    return out


def parse_udp(data: bytes, src_ip: str, dst_ip: str) -> tuple[dict, bytes]:
    """UDP 데이터그램 → (필드 dict, 페이로드 bytes).

    src_ip, dst_ip: 의사 헤더를 만들 IP 주소 ("10.0.2.15" 형식)
    dict 키: src_port, dst_port, length, checksum,
             checksum_ok(True / False / None=체크섬 안 씀 또는 잘려서 검증 불가)
    """
    if len(data) < UDP_HEADER_LEN:
        raise ValueError(f"UDP header too short: {len(data)} bytes")
    sport, dport, length, checksum = struct.unpack("!HHHH", data[:UDP_HEADER_LEN])
    if length < UDP_HEADER_LEN:
        raise ValueError(f"bad UDP length: {length}")

    complete = length <= len(data)
    datagram = data[:length] if complete else data
    ok = udp_checksum_ok(datagram, src_ip, dst_ip) if (checksum and complete) else None
    info = {
        "src_port": sport,
        "dst_port": dport,
        "length": length,
        "checksum": checksum,
        "checksum_ok": ok,
        # 틀린 값이 의사 헤더 합 그대로면 offload 미완성 값 (진짜 손상이 아님)
        "checksum_partial": ok is False and checksum == _pseudo_sum(src_ip, dst_ip, length),
    }
    return info, datagram[UDP_HEADER_LEN:]


def _pseudo_header(src_ip: str, dst_ip: str, length: int) -> bytes:
    return (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
            + struct.pack("!BBH", 0, IP_PROTO_UDP, length))


def _pseudo_sum(src_ip: str, dst_ip: str, length: int) -> int:
    """의사 헤더만의 16비트 1의 보수 합 (보수를 취하기 전). offload 때 체크섬 칸에 들어가는 값."""
    return ~ip_checksum(_pseudo_header(src_ip, dst_ip, length)) & 0xFFFF


def udp_checksum_ok(datagram: bytes, src_ip: str, dst_ip: str) -> Optional[bool]:
    """의사 헤더 + UDP 데이터그램(체크섬 칸 포함)의 1의 보수 합이 0이면 True."""
    return ip_checksum(_pseudo_header(src_ip, dst_ip, len(datagram)) + datagram) == 0
