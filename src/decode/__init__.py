# =============================================================================
# 담당자  : A
# 맡은 기능: F2 계층별 해석 — decode(): 계층 파서 합치기
#            - parse_ethernet → parse_ip → parse_tcp/parse_udp · parse_icmp → parse_app 순서로 호출
#            - 응용 계층은 parse_app()(B) 하나만 부른다. 프로토콜 판별은 parse_app()이 한다
#            - IPv4가 아니면 None
#            - 하위 파서의 예외(ValueError 등)는 잡아서 해당 계층만 None으로 두고 계속 진행
# 완료 기준: Ethernet·IP·TCP/UDP·ICMP·응용 결과가 PacketInfo 하나에 담긴다.
#            하위 파서가 미구현이거나 깨져도 프로그램이 멈추지 않는다.
# =============================================================================
from __future__ import annotations

import sys
from typing import Callable, Optional, TypeVar

from ..models import DEFAULT_PORTS, Captured, PacketInfo, canonical_key

__all__ = ["decode"]

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


def decode(captured: Captured,
           ports: Optional[dict[str, tuple[int, ...]]] = None) -> Optional[PacketInfo]:
    """Captured → PacketInfo, 해석 대상이 아니면(IPv4 아님 등) None.

    ports: 응용 프로토콜 포트 표 (models.DEFAULT_PORTS 형식, --port 로 바뀐 값)
    """
    # 하위 파서는 여기(함수 안)에서 불러온다. 파일 맨 위로 옮기지 말 것.
    # → 한 사람 파일의 오류가 다른 사람의 단위 테스트(src.decode.* import)를 깨뜨리지 않게 하기 위함.
    from .app_select import parse_app              # B
    from .icmp import parse_icmp                   # B
    from .link_ip import parse_ethernet, parse_ip  # A
    from .transport import parse_tcp, parse_udp    # A

    if ports is None:
        ports = DEFAULT_PORTS

    # --- L2·L3: Ethernet, IPv4 --- (여기서 실패하면 PacketInfo를 만들 수 없음 → None)
    try:
        eth, ethertype, l3 = parse_ethernet(captured.frame)
        if ethertype != ETHERTYPE_IPV4:
            return None
        ip, l4 = parse_ip(l3)
    except ValueError:
        return None

    pkt = PacketInfo(
        no=captured.no,
        ts=captured.ts,
        direction=captured.direction,
        frame_len=len(captured.frame),
        eth=eth,
        ip=ip,
        proto=ip["proto_name"],
    )

    # 조각난 IP의 두 번째 이후 조각에는 전송 계층 헤더가 없다.
    if ip["frag_offset"] != 0:
        pkt.payload = l4
        return pkt

    # --- L4: TCP / UDP / ICMP ---
    if pkt.proto in ("TCP", "UDP"):
        if pkt.proto == "TCP":
            result = _check_pair("parse_tcp", _safe("parse_tcp", parse_tcp, l4))
        else:
            # UDP 체크섬 검증에 의사 헤더(출발지·목적지 IP)가 필요하다
            result = _check_pair("parse_udp", _safe("parse_udp", parse_udp, l4,
                                                    ip["src_ip"], ip["dst_ip"]))
        if result is None:
            return pkt
        fields, pkt.payload = result
        if pkt.proto == "TCP":
            pkt.tcp = fields
        else:
            pkt.udp = fields
    elif pkt.proto == "ICMP":
        icmp = _safe("parse_icmp", parse_icmp, l4)
        pkt.icmp = icmp if isinstance(icmp, dict) else None
        return pkt
    else:
        pkt.payload = l4
        return pkt

    # --- L7: 응용 계층 (판별은 parse_app이 함) ---
    sport, dport = pkt.src_port, pkt.dst_port
    if pkt.payload and sport is not None and dport is not None:
        key = canonical_key(pkt.src_ip, sport, pkt.dst_ip, dport)
        pkt.app = _safe("parse_app", parse_app, key, pkt.proto, sport, dport, pkt.payload, ports)

    return pkt


def _check_pair(name: str, result) -> Optional[tuple[dict, bytes]]:
    """파서 결과가 약속한 모양 (dict, bytes)인지 확인. 아니면 한 번 경고하고 None."""
    if result is None:
        return None
    if (isinstance(result, tuple) and len(result) == 2
            and isinstance(result[0], dict) and isinstance(result[1], (bytes, bytearray))
            and "src_port" in result[0] and "dst_port" in result[0]):
        return result[0], bytes(result[1])
    key = name + ":shape"
    if key not in _reported:
        _reported.add(key)
        print(f"[decode] {name}가 약속과 다른 값을 돌려줌 ({type(result).__name__}) — "
              f"(src_port·dst_port가 있는 dict, 나머지 bytes) 형식이어야 합니다", file=sys.stderr)
    return None
