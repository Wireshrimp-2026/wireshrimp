# =============================================================================
# 담당자  : A
# 맡은 기능: F4 화면·로그 출력 (DESIGN 4장)
#            - 4.1 패킷별 출력: 번호·시각·방향·주소 한 줄 + [ETH] [IP] [TCP]/[UDP]/[ICMP] + 응용(app.lines)
#              응용을 판별 못 한 데이터는 [DATA] N bytes + 앞 32바이트 hex, hex=True면 원본 덤프
#              IP·UDP 체크섬: ok / bad, OUT이고 bad면 offload, UDP checksum_ok가 None이면 unused
#            - 4.2 TCP 연결 요약 (연결설정 / 데이터 / 연결해제, RST, 캡처 전에 열린 연결)
#            - 4.3 traceroute 홉 표
#            - open_log()가 불렸으면 화면과 같은 내용을 파일에도 쓴다
# 완료 기준: 4.1·4.2·4.3 형식이 모두 찍히고 로그 파일에도 같은 내용이 남는다.
# =============================================================================
from __future__ import annotations

from .models import Connection, Hop, PacketInfo


def open_log(path: str) -> None:
    """이후 출력을 path 파일에도 기록한다."""
    raise NotImplementedError


def close_log() -> None:
    """로그 파일을 닫는다 (열려 있지 않으면 아무것도 안 함)."""
    raise NotImplementedError


def print_packet(pkt: PacketInfo, hex: bool = False) -> None:
    """패킷 1건을 4.1 형식으로 출력."""
    raise NotImplementedError


def print_connection(conn: Connection) -> None:
    """TCP 연결 1개를 4.2 형식으로 출력."""
    raise NotImplementedError


def print_route(dst: str, hops: list[Hop]) -> None:
    """목적지 1곳의 traceroute 결과를 4.3 형식 홉 표로 출력."""
    raise NotImplementedError
