# =============================================================================
# 담당자  : B
# 맡은 기능: ICMP 해석 (DESIGN 7.7)
#            - Type, Code, Checksum, type_name
#              (Destination Unreachable은 Code 뜻도 괄호로: "Destination Unreachable (Port Unreachable)")
#            - Echo Request(8) / Reply(0): Identifier, Sequence
#            - Time Exceeded(11) / Destination Unreachable(3) 등 오류 메시지: 안에 담긴 원본 IP 헤더 + 앞 8바이트
#              → orig_src_ip, orig_dst_ip, orig_proto, orig_ttl, (UDP·TCP면) orig_src_port, orig_dst_port,
#                (ICMP Echo면) orig_id, orig_seq — traceroute -I 짝 맞추기용 (#18)
#              원본이 두 번째 이후 IP 조각이면 앞 8바이트가 전송 계층 헤더가 아니므로 포트·id는 None
#            - 돌려주는 dict는 늘 같은 키. 해당 없거나 알 수 없는 값은 None
#            - 데이터가 짧거나 깨졌으면 ValueError (ICMP 헤더 8바이트 미만, 오류 메시지 안 원본 IP 헤더가 잘림)
# 완료 기준: ICMP Type·Code와 안쪽 원본 IP·포트가 PacketInfo.icmp에 담긴다.
# =============================================================================
from __future__ import annotations

import socket
import struct
from typing import Optional

HEADER_LEN = 8                 # Type 1 + Code 1 + Checksum 2 + (Echo면 Identifier 2 + Sequence 2)
IP_MIN_HEADER_LEN = 20

ECHO_REPLY = 0
DEST_UNREACHABLE = 3
ECHO_REQUEST = 8
TIME_EXCEEDED = 11

TYPE_NAMES = {0: "Echo Reply", 3: "Destination Unreachable", 4: "Source Quench", 5: "Redirect",
              8: "Echo Request", 9: "Router Advertisement", 10: "Router Solicitation",
              11: "Time Exceeded", 12: "Parameter Problem", 13: "Timestamp Request",
              14: "Timestamp Reply"}
# Destination Unreachable(3)의 Code (RFC 792·1122·1812)
UNREACHABLE_CODES = {0: "Network Unreachable", 1: "Host Unreachable", 2: "Protocol Unreachable",
                     3: "Port Unreachable", 4: "Fragmentation Needed", 5: "Source Route Failed",
                     6: "Network Unknown", 7: "Host Unknown", 8: "Source Host Isolated",
                     9: "Network Prohibited", 10: "Host Prohibited", 11: "Network Unreachable for TOS",
                     12: "Host Unreachable for TOS", 13: "Communication Prohibited",
                     14: "Host Precedence Violation", 15: "Precedence Cutoff"}
ECHO_TYPES = (ECHO_REPLY, ECHO_REQUEST)
# 원본 IP 헤더 + 앞 8바이트를 담는 오류 메시지 (Destination Unreachable, Source Quench, Redirect,
# Time Exceeded, Parameter Problem)
ERROR_TYPES = (3, 4, 5, 11, 12)


def parse_icmp(data: bytes) -> dict:
    """ICMP 메시지 → 필드 dict (키는 models.PacketInfo.icmp 주석 참고). 짧거나 깨졌으면 ValueError.

    키: type, code, type_name, checksum, id, seq,
        orig_src_ip, orig_dst_ip, orig_proto, orig_ttl, orig_src_port, orig_dst_port, orig_id, orig_seq
    """
    if len(data) < HEADER_LEN:
        raise ValueError(f"ICMP message too short: {len(data)} bytes")
    icmp_type, code, checksum, word1, word2 = struct.unpack_from("!BBHHH", data)
    info = {"type": icmp_type, "code": code, "type_name": type_name(icmp_type, code),
            "checksum": checksum, "id": None, "seq": None,
            "orig_src_ip": None, "orig_dst_ip": None, "orig_proto": None, "orig_ttl": None,
            "orig_src_port": None, "orig_dst_port": None, "orig_id": None, "orig_seq": None}
    if icmp_type in ECHO_TYPES:
        info["id"], info["seq"] = word1, word2
    elif icmp_type in ERROR_TYPES:
        info.update(_original(data[HEADER_LEN:]))
    return info


def _original(inner: bytes) -> dict:
    """오류 메시지 안의 원본 패킷(IP 헤더 + 앞 8바이트) → orig_* 값."""
    if len(inner) < IP_MIN_HEADER_LEN:
        raise ValueError(f"ICMP error: original IP header truncated ({len(inner)} bytes)")
    version, ihl = inner[0] >> 4, (inner[0] & 0x0F) * 4
    if version != 4:
        raise ValueError(f"ICMP error: original packet is not IPv4 (version={version})")
    if ihl < IP_MIN_HEADER_LEN or len(inner) < ihl:
        raise ValueError(f"ICMP error: bad original IP header length {ihl} ({len(inner)} bytes)")
    flags_frag, ttl, proto = struct.unpack_from("!HBB", inner, 6)
    out = {"orig_src_ip": socket.inet_ntoa(inner[12:16]), "orig_dst_ip": socket.inet_ntoa(inner[16:20]),
           "orig_proto": proto, "orig_ttl": ttl}
    l4 = inner[ihl:]
    if flags_frag & 0x1FFF:              # 두 번째 이후 조각: 뒤 8바이트는 전송 계층 헤더가 아님
        return out
    if proto in (6, 17) and len(l4) >= 4:                          # TCP·UDP: 앞 4바이트가 포트
        out["orig_src_port"], out["orig_dst_port"] = struct.unpack_from("!HH", l4)
    elif proto == 1 and len(l4) >= 8 and l4[0] in ECHO_TYPES:      # ICMP Echo: id·seq
        out["orig_id"], out["orig_seq"] = struct.unpack_from("!HH", l4, 4)
    return out


def type_name(icmp_type: int, code: int) -> Optional[str]:
    """출력용 이름. 모르는 Type이면 None. 예: "Time Exceeded", "Destination Unreachable (Port Unreachable)"."""
    name = TYPE_NAMES.get(icmp_type)
    if icmp_type == DEST_UNREACHABLE and code in UNREACHABLE_CODES:
        return f"{name} ({UNREACHABLE_CODES[code]})"
    return name


def describe(icmp_type: int, code: int) -> str:
    """홉 표(DESIGN 4.3)용 짧은 설명: "11/0 Time Exceeded", "3/3 Port Unreachable", "0/0 Echo Reply"."""
    name = UNREACHABLE_CODES.get(code) if icmp_type == DEST_UNREACHABLE else None
    name = name or TYPE_NAMES.get(icmp_type)
    return f"{icmp_type}/{code}" + (f" {name}" if name else "")
