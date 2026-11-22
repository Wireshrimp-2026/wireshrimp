# =============================================================================
# 담당자  : B
# 맡은 기능: 응용 계층 진입점 — 프로토콜 판별 (DESIGN 3.1)
#            - 포트 표(ports)와 내용으로 프로토콜을 골라 app_* 파서 하나를 부른다
#              HTTP(80·8080) / DNS(53, TCP면 over_tcp=True) / SMTP(25·587) / POP3(110) / IMAP(143)
#              TLS(443·465·993·995) / BitTorrent 트래커(/announce) · 피어(handshake 시그니처) · DHT(bencode)
#            - 트래커는 parse_bt_tracker()를 먼저, None이면 parse_http()
#            - 피어 handshake가 한 번 보인 연결은 이후에도 BitTorrent 피어로 본다 (conn_key별 기억)
#            - 메일 파서의 from_client: 상대 포트가 메일 포트면 클라이언트 → 서버
#            - 돌려주는 AppInfo 형식(lines는 list[str])을 여기서 검사한다 → 틀리면 TypeError
#              (decode()가 잡아 한 번만 알리고 [DATA]로 넘어감. 출력 단계에서 프로그램이 멈추지 않게)
# 진행 상황: HTTP·DNS 분기 (#10). TLS·메일·BitTorrent 분기는 각 파서를 만들 때 추가 (#13~#17)
# 완료 기준: 3.1 표대로 프로토콜이 골라진다. 해당 없음이면 None.
# =============================================================================
from __future__ import annotations

from typing import Iterable, Optional

from ..models import AppInfo, ConnKey

# 내용으로 HTTP를 알아보는 첫 줄 시작 (포트가 80·8080이 아니어도 HTTP로 본다)
HTTP_STARTS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ",
               b"CONNECT ", b"TRACE ", b"HTTP/1.")

# 포트로 고를 때 확인하는 순서. 앞에 있는 것이 먼저 (두 포트가 서로 다른 프로토콜에 걸릴 때)
TCP_BY_PORT = ("dns", "http")
UDP_BY_PORT = ("dns",)


def parse_app(conn_key: ConnKey, proto: str, src_port: int, dst_port: int,
              payload: bytes, ports: dict[str, tuple[int, ...]]) -> Optional[AppInfo]:
    """전송 계층 페이로드 → AppInfo 또는 None (판별 못 함).

    conn_key: models.canonical_key()로 만든 방향 무관 연결 키
    proto:    "TCP" / "UDP"
    ports:    models.DEFAULT_PORTS 형식의 포트 표 (--port 로 바뀐 값)

    하위 파서의 ValueError(짧거나 깨진 데이터)는 그대로 올린다 → decode()가 잡아 app=None.
    """
    if not payload:
        return None
    if proto == "UDP":
        return _checked(_parse_udp(payload, src_port, dst_port, ports))
    if proto == "TCP":
        return _checked(_parse_tcp(payload, src_port, dst_port, ports))
    return None


def _parse_udp(payload: bytes, src_port: int, dst_port: int,
               ports: dict[str, tuple[int, ...]]) -> Optional[AppInfo]:
    name = match_port(UDP_BY_PORT, ports, src_port, dst_port)
    if name == "dns":
        from .app_dns import parse_dns
        return parse_dns(payload, over_tcp=False)
    return None        # traceroute 프로브(33434~) 등은 응용 계층이 아님


def _parse_tcp(payload: bytes, src_port: int, dst_port: int,
               ports: dict[str, tuple[int, ...]]) -> Optional[AppInfo]:
    # 하위 파서는 필요할 때 불러온다 → 아직 만드는 중인 다른 파서 파일이 깨져 있어도 이 분기는 돈다
    name = match_port(TCP_BY_PORT, ports, src_port, dst_port)
    if name == "dns":
        from .app_dns import parse_dns
        return parse_dns(payload, over_tcp=True)      # 앞 2바이트 길이는 parse_dns가 뗀다
    if name == "http" or looks_like_http(payload):
        from .app_http import parse_http
        return parse_http(payload)
    return None


def match_port(names: Iterable[str], ports: dict[str, tuple[int, ...]],
               src_port: int, dst_port: int) -> Optional[str]:
    """포트 표에서 프로토콜 이름을 찾는다. 없으면 None.

    목적지 포트(클라이언트 → 서버)를 먼저 보고, 없으면 출발지 포트(서버 → 클라이언트).
    """
    for port in (dst_port, src_port):
        for name in names:
            if port in ports.get(name, ()):
                return name
    return None


def looks_like_http(payload: bytes) -> bool:
    """첫 줄이 HTTP 요청줄(GET / …)이나 상태줄(HTTP/1.x …)로 시작하는지."""
    return payload.startswith(HTTP_STARTS)


def _checked(app) -> Optional[AppInfo]:
    """하위 파서가 약속한 AppInfo 형식(DESIGN 5.3)을 돌려줬는지 확인. 틀리면 TypeError."""
    if app is None:
        return None
    if not isinstance(app, AppInfo):
        raise TypeError(f"AppInfo가 아닌 값: {type(app).__name__}")
    if not isinstance(app.name, str) or not isinstance(app.summary, str):
        raise TypeError(f"{app.name!r}: name·summary는 str이어야 함")
    if not isinstance(app.lines, list):
        raise TypeError(f"{app.name}: lines는 list여야 함 ({type(app.lines).__name__})")
    for line in app.lines:
        if not isinstance(line, str):
            raise TypeError(f"{app.name}: lines에 str이 아닌 값 ({type(line).__name__}: {line!r:.40})")
    if not isinstance(app.fields, dict):
        raise TypeError(f"{app.name}: fields는 dict여야 함 ({type(app.fields).__name__})")
    return app
