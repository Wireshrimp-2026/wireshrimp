# =============================================================================
# 담당자  : A
# 맡은 기능: F2 계층별 해석 — Ethernet(14B), IPv4(20B~) 헤더 파싱
#            - Ethernet: 출발지·목적지 MAC, EtherType (0x0800 → IPv4)
#            - IP: 버전, 헤더 길이, TTL, Protocol(6 TCP / 17 UDP / 1 ICMP), 출발지·목적지 IP
#            - 여러 바이트 필드는 big-endian → struct "!" 형식
#            - 데이터가 짧거나 깨졌으면 ValueError
# 완료 기준: sudo 실행 시 curl http://neverssl.com 트래픽이 OUT/IN 구분되어
#            PacketInfo로 나온다. IP·TTL이 Wireshark와 일치한다.
#            실험 스크립트로 조건별 반복 실행 시 CSV가 쌓인다.
# =============================================================================
from __future__ import annotations

import socket
import struct

ETH_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100      # 802.1Q 태그 (4바이트 더 붙음)
IPV4_MIN_HEADER_LEN = 20

# IP Protocol 번호 → PacketInfo.proto 문자열
IP_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def mac_to_str(raw: bytes) -> str:
    """6바이트 MAC → "aa:bb:cc:dd:ee:ff"."""
    return ":".join(f"{b:02x}" for b in raw)


def parse_ethernet(frame: bytes) -> tuple[dict, int, bytes]:
    """이더넷 프레임 → ({"src_mac", "dst_mac"}, EtherType, 나머지 bytes)."""
    if len(frame) < ETH_HEADER_LEN:
        raise ValueError(f"ethernet frame too short: {len(frame)} bytes")

    dst, src, ethertype = struct.unpack("!6s6sH", frame[:ETH_HEADER_LEN])
    rest = frame[ETH_HEADER_LEN:]

    # VLAN 태그가 있으면 한 겹 벗겨서 진짜 EtherType을 꺼낸다.
    if ethertype == ETHERTYPE_VLAN:
        if len(rest) < 4:
            raise ValueError("VLAN tag too short")
        _tci, ethertype = struct.unpack("!HH", rest[:4])
        rest = rest[4:]

    info = {"src_mac": mac_to_str(src), "dst_mac": mac_to_str(dst)}
    return info, ethertype, rest


def parse_ip(data: bytes) -> tuple[dict, bytes]:
    """IPv4 패킷 → ({"version", "ihl", "ttl", "protocol", "src_ip", "dst_ip", ...}, 나머지 bytes).

    나머지 bytes는 IP 헤더 뒤의 전송 계층 데이터이며, total_length 기준으로 잘라
    이더넷 최소 길이(60B)를 채우려고 붙은 padding을 떼어 낸다.
    """
    if len(data) < IPV4_MIN_HEADER_LEN:
        raise ValueError(f"IPv4 header too short: {len(data)} bytes")

    (ver_ihl, tos, total_length, ident, flags_frag,
     ttl, protocol, checksum, src, dst) = struct.unpack("!BBHHHBBH4s4s", data[:IPV4_MIN_HEADER_LEN])

    version = ver_ihl >> 4
    ihl = ver_ihl & 0x0F             # 32비트 워드 단위
    header_len = ihl * 4
    if version != 4:
        raise ValueError(f"not IPv4 (version={version})")
    if ihl < 5:
        raise ValueError(f"bad IHL: {ihl}")
    if len(data) < header_len:
        raise ValueError(f"IPv4 options truncated: need {header_len}, got {len(data)}")
    if total_length == 0 and len(data) > 0xFFFF:
        # BIG TCP(GSO) 프레임: 64KB를 넘으면 커널이 total_length를 0으로 둔다 → 실제 길이 사용
        total_length = len(data)
    if total_length < header_len:
        raise ValueError(f"bad total_length: {total_length} < header {header_len}")

    # total_length보다 짧게 잡힌 경우(snaplen 등)는 있는 만큼만 사용
    end = min(total_length, len(data))
    payload = data[header_len:end]

    info = {
        "version": version,
        "ihl": ihl,
        "header_len": header_len,
        "tos": tos,
        "total_length": total_length,
        "id": ident,
        "flags": flags_frag >> 13,                 # bit0 reserved, bit1 DF, bit2 MF
        "dont_fragment": bool(flags_frag & 0x4000),
        "more_fragments": bool(flags_frag & 0x2000),
        "frag_offset": (flags_frag & 0x1FFF) * 8,  # 바이트 단위
        "ttl": ttl,
        "protocol": protocol,
        "proto_name": IP_PROTO_NAMES.get(protocol, "OTHER"),
        "checksum": checksum,
        "src_ip": socket.inet_ntoa(src),
        "dst_ip": socket.inet_ntoa(dst),
    }
    return info, payload
