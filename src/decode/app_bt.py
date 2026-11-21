# =============================================================================
# 담당자  : B
# 맡은 기능: BitTorrent 해석 (DESIGN 7.8) — 선택
#            - bencode 해석기: 정수 i…e, 문자열 길이:값, 리스트 l…e, 사전 d…e
#            - 트래커 요청 (HTTP GET /announce?…): info_hash(→ 40자리 hex), peer_id, port,
#              uploaded, downloaded, left, event, compact
#            - 트래커 응답 (bencode): interval, complete, incomplete, peers(compact 6바이트 → IP:port)
#            - 피어 handshake: pstrlen(19), pstr, reserved 8B, info_hash, peer_id
#            - 피어 메시지: 4B 길이 + ID — keep-alive, choke(0), unchoke(1), interested(2),
#              not interested(3), have(4), bitfield(5), request(6), piece(7), cancel(8), extended(20)
#            - piece처럼 여러 세그먼트에 걸친 메시지: conn_key별 "남은 바이트"를 이 파일 안에서 기억
#            - DHT (UDP, KRPC): t, y(q/r/e), q(ping, find_node, get_peers, announce_peer)
# 완료 기준: handshake의 info_hash·peer_id, 트래커 요청 인자와 응답의 peers 목록,
#            피어 메시지 종류, DHT 질의 종류가 AppInfo로 나온다.
# =============================================================================
from __future__ import annotations

from typing import Optional

from ..models import AppInfo, ConnKey

HANDSHAKE_PREFIX = b"\x13BitTorrent protocol"


def bdecode(data: bytes):
    """bencode bytes → int / bytes / list / dict. 깨졌으면 ValueError."""
    raise NotImplementedError


def parse_bt_tracker(data: bytes) -> Optional[AppInfo]:
    """트래커 요청(GET /announce…) 또는 응답(HTTP + bencode) → AppInfo(name="BT-TRACKER"), 아니면 None."""
    raise NotImplementedError


def parse_bt_peer(conn_key: ConnKey, data: bytes) -> Optional[AppInfo]:
    """피어 연결 세그먼트 → AppInfo(name="BT-PEER"), BitTorrent가 아니면 None."""
    raise NotImplementedError


def parse_bt_dht(data: bytes) -> Optional[AppInfo]:
    """UDP 페이로드 → AppInfo(name="BT-DHT"), KRPC가 아니면 None."""
    raise NotImplementedError
