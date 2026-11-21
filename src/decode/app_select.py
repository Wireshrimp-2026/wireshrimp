# =============================================================================
# 담당자  : B
# 맡은 기능: 응용 계층 진입점 — 프로토콜 판별 (DESIGN 3.1)
#            - 포트 표(ports)와 내용으로 프로토콜을 골라 app_* 파서 하나를 부른다
#              HTTP(80·8080) / DNS(53, TCP면 over_tcp=True) / SMTP(25·587) / POP3(110) / IMAP(143)
#              TLS(443·465·993·995) / BitTorrent 트래커(/announce) · 피어(handshake 시그니처) · DHT(bencode)
#            - 트래커는 parse_bt_tracker()를 먼저, None이면 parse_http()
#            - 피어 handshake가 한 번 보인 연결은 이후에도 BitTorrent 피어로 본다 (conn_key별 기억)
#            - 메일 파서의 from_client: 상대 포트가 메일 포트면 클라이언트 → 서버
# 완료 기준: 3.1 표대로 프로토콜이 골라진다. 해당 없음이면 None.
# =============================================================================
from __future__ import annotations

from typing import Optional

from ..models import AppInfo, ConnKey


def parse_app(conn_key: ConnKey, proto: str, src_port: int, dst_port: int,
              payload: bytes, ports: dict[str, tuple[int, ...]]) -> Optional[AppInfo]:
    """전송 계층 페이로드 → AppInfo 또는 None (판별 못 함).

    conn_key: models.canonical_key()로 만든 방향 무관 연결 키
    proto:    "TCP" / "UDP"
    ports:    models.DEFAULT_PORTS 형식의 포트 표 (--port 로 바뀐 값)
    """
    raise NotImplementedError
