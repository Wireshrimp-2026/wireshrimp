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

import sys
from typing import Callable, Optional, TypeVar

from ..models import Captured, PacketInfo

__all__ = ["decode"]

DNS_PORT = 53
HTTP_PORT = 80
ETHERTYPE_IPV4 = 0x0800

# 같은 파서 오류를 패킷마다 찍지 않도록, 파서별로 처음 한 번만 stderr에 알린다.
_reported: set[str] = set()

T = TypeVar("T")


def _safe(name: str, fn: Callable[..., T], *args) -> Optional[T]:
    """하위 파서를 호출하고, 어떤 예외든 잡아서 None을 돌려준다.

    ValueError(짧거나 깨진 데이터)는 정상적인 실패로 보고 조용히 넘긴다.
    그 밖의 예외(NotImplementedError, 버그)는 파서별로 한 번만 경고를 찍는다.
    """
    try:
        return fn(*args)
    except ValueError:
        return None
    except Exception as e:  # noqa: BLE001 — 한 사람의 버그가 전체를 멈추지 않게
        if name not in _reported:
            _reported.add(name)
            reason = "아직 미구현" if isinstance(e, NotImplementedError) else f"{type(e).__name__}: {e}"
            print(f"[decode] {name} 실패 ({reason}) — 이 계층은 None으로 둡니다", file=sys.stderr)
        return None


def decode(captured: Captured) -> Optional[PacketInfo]:
    """Captured → PacketInfo, 해석 대상이 아니면(IPv4 아님 등) None."""
    # 하위 파서는 여기(함수 안)에서 불러온다. 파일 맨 위로 옮기지 말 것.
    # → 한 사람 파일의 오류가 다른 팀원의 단위 테스트(src.decode.* import)를 깨뜨리지 않게 하기 위함.
    from .app_dns import parse_dns                # C
    from .app_http import parse_http              # C
    from .icmp import parse_icmp                  # D
    from .link_ip import parse_ethernet, parse_ip  # A
    from .transport import parse_tcp, parse_udp   # B

    # --- L2: Ethernet ---  (여기서 실패하면 PacketInfo를 만들 수 없음 → None)
    try:
        eth, ethertype, l3 = parse_ethernet(captured.frame)
        if ethertype != ETHERTYPE_IPV4:
            return None
        ip, l4 = parse_ip(l3)
    except ValueError:
        return None

    pkt = PacketInfo(
        ts=captured.ts,
        direction=captured.direction,
        src_mac=eth["src_mac"],
        dst_mac=eth["dst_mac"],
        src_ip=ip["src_ip"],
        dst_ip=ip["dst_ip"],
        ttl=ip["ttl"],
        proto=ip["proto_name"],
    )

    # 조각난 IP의 두 번째 이후 조각에는 전송 계층 헤더가 없다.
    if ip["frag_offset"] != 0:
        pkt.payload_len = len(l4)
        return pkt

    # --- L4: TCP / UDP (B) · ICMP (D) ---
    payload: Optional[bytes] = None
    if pkt.proto in ("TCP", "UDP"):
        parser = parse_tcp if pkt.proto == "TCP" else parse_udp
        name = f"parse_{pkt.proto.lower()}"
        result = _check_pair(name, _safe(name, parser, l4))
        if result is not None:
            fields, payload = result
            _apply(pkt, fields, ("src_port", "dst_port", "tcp_flags", "seq", "ack",
                                 "window", "udp_length"))
            pkt.payload_len = len(payload)
    elif pkt.proto == "ICMP":
        result = _check_pair("parse_icmp", _safe("parse_icmp", parse_icmp, l4))
        if result is not None:
            fields, _rest = result
            _apply(pkt, fields, ("icmp_type", "icmp_code", "icmp_orig_dst_ip",
                                 "icmp_orig_dst_port"))
        pkt.payload_len = 0
    else:
        pkt.payload_len = len(l4)

    # --- L7: DNS / HTTP (C) ---
    if payload:
        ports = (pkt.src_port, pkt.dst_port)
        if DNS_PORT in ports:
            dns_data = payload
            if pkt.proto == "TCP":
                # DNS over TCP는 앞에 2바이트 길이가 붙는다.
                dns_data = payload[2:] if len(payload) > 2 else b""
            if dns_data:
                pkt.dns = _safe("parse_dns", parse_dns, dns_data)
        elif pkt.proto == "TCP" and HTTP_PORT in ports:
            pkt.http = _safe("parse_http", parse_http, payload)

    return pkt


def _check_pair(name: str, result) -> Optional[tuple[dict, bytes]]:
    """파서 결과가 약속한 모양 (dict, bytes)인지 확인. 아니면 한 번 경고하고 None.

    _safe()는 파서 '호출' 중 예외만 잡으므로, 모양이 틀린 값을 돌려주면 여기서 막지 않을 경우
    풀어 담는 순간 예외가 나서 프로그램 전체가 멈춘다.
    """
    if result is None:
        return None
    if (isinstance(result, tuple) and len(result) == 2
            and isinstance(result[0], dict) and isinstance(result[1], (bytes, bytearray))):
        return result
    key = name + ":shape"
    if key not in _reported:
        _reported.add(key)
        print(f"[decode] {name}가 약속과 다른 값을 돌려줌 ({type(result).__name__}) — "
              f"(필드 dict, 나머지 bytes) 형식이어야 합니다", file=sys.stderr)
    return None


def _apply(pkt: PacketInfo, fields: dict, keys: tuple[str, ...]) -> None:
    """하위 파서가 돌려준 dict에서 PacketInfo 필드에 해당하는 값만 옮겨 담는다."""
    for key in keys:
        if key in fields:
            setattr(pkt, key, fields[key])
