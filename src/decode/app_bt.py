# =============================================================================
# 담당자  : B
# 맡은 기능: BitTorrent 해석 (DESIGN 7.8) — 선택
#            - bencode 해석기: 정수 i…e, 문자열 길이:값, 리스트 l…e, 사전 d…e (깨졌으면 ValueError)
#            - 트래커 요청 (HTTP GET …?info_hash=…, announce·scrape): info_hash(URL 디코딩 → 40자리 hex),
#              peer_id, port, uploaded, downloaded, left, event, compact (+ numwant, Host·User-Agent 헤더)
#            - 트래커 응답 (HTTP + bencode): interval, complete, incomplete, peers(compact 6바이트 → IP:port,
#              사전 목록도), failure reason, scrape 응답의 files. chunked·gzip 본문은 풀어서 본다 (크기 상한)
#            - 피어 handshake: pstrlen(19), pstr, reserved 8B(확장 비트), info_hash, peer_id
#            - 피어 메시지: 4B 길이 + ID — keep-alive, choke(0)·unchoke(1)·interested(2)·not interested(3),
#              have(4), bitfield(5), request(6), piece(7), cancel(8), port(9), Fast 확장(13~17),
#              extended(20: 확장 handshake의 v·p·m, 그 뒤 확장 메시지는 m으로 이름을 붙임), v2 해시(21~23)
#            - 한 세그먼트의 여러 메시지를 모두 해석. piece처럼 세그먼트를 걸친 메시지는 "남은 바이트"를,
#              세그먼트 끝에서 잘린 머리는 그 바이트를 이 파일 안에 기억해 다음 메시지 시작을 찾는다
#            - 메시지 경계는 방향마다 따로다 → parse_app()이 conn_key를 "보내는 쪽 → 받는 쪽" 순서로 넘긴다
#            - 길이·ID가 말이 안 되면(캡처 손실·재전송) 그 방향은 "메시지 경계를 잃음"으로 표시하고,
#              자주 나오는 메시지 머리(handshake, 16 KiB piece, request, have)를 찾으면 거기서 다시 해석
#              piece가 끝나기 전에 다음 piece 머리가 보이면(그 사이 세그먼트를 놓쳤거나 재전송) 거기서 바로 다시 해석
#            - DHT (UDP, KRPC): t, y(q/r/e), q(ping, find_node, get_peers, announce_peer)와 인자,
#              응답의 nodes·values·token, 오류 코드, BEP 42 ip
#            - 화면에 찍는 값은 제어 문자를 \xNN으로 바꾸고 너무 길면 자른다. 줄이 많으면 MAX_ITEMS개까지
#            - 기억하는 상태는 크기 제한 (연결 방향 MAX_FLOWS개, 가장 오래 안 쓴 것부터 잊음)
#            - 해석하지 않는 것: 암호화(MSE) 연결, uTP(UDP 위 피어 연결), UDP 트래커(BEP 15), HTTPS 트래커
# 완료 기준: handshake의 info_hash·peer_id, 트래커 요청 인자와 응답의 peers 목록,
#            피어 메시지 종류, DHT 질의 종류가 AppInfo로 나온다.
# =============================================================================
from __future__ import annotations

import ipaddress
import re
import struct
import zlib
from collections import OrderedDict
from typing import Optional
from urllib.parse import unquote_to_bytes

from ..models import AppInfo, ConnKey

HANDSHAKE_PREFIX = b"\x13BitTorrent protocol"
HANDSHAKE_LEN = 68           # pstrlen 1 + pstr 19 + reserved 8 + info_hash 20 + peer_id 20

MAX_FLOWS = 512              # 메시지 경계를 기억할 연결 방향 수 (연결 하나에 둘). 넘으면 오래 안 쓴 것부터 잊음
MAX_DEPTH = 32               # bencode 중첩 깊이 상한
MAX_DIGITS = 64              # bencode 정수 자릿수 상한
MAX_MESSAGE = 1 << 21        # 피어 메시지 길이 상한 (2 MiB). 넘으면 경계를 잃은 것으로 본다
MAX_BLOCK = 1 << 17          # piece 블록 크기 상한 (128 KiB, 보통 16 KiB)
MAX_EXTENDED = 4096          # 이 길이까지의 확장 handshake는 다 모아서 bencode를 본다
MAX_BODY = 1 << 20           # 트래커 응답 본문을 풀 때(chunked·gzip) 최대 바이트
MAX_PARAMS = 256             # 트래커 요청에서 읽을 인자 수
MAX_ITEMS = 20               # 세그먼트 하나에서 찍을 줄 수 (summary 포함). 넘으면 나머지는 개수만
MAX_PEERS = 10               # 화면에 보여 줄 peers·info_hash·파일 수 (나머지는 개수만)
MAX_ADDRS = 4                # DHT nodes·values는 한 줄에 앞 몇 개만
MAX_KEEP = 200               # fields에 남길 peers·nodes·values 수
MAX_EXT_NAMES = 32           # 확장 handshake의 m에서 기억할 이름 수
MAX_SHOW = 200               # 화면 한 줄 최대 글자 수
NEST = "  "                  # 안쪽 줄 들여쓰기

MESSAGES = {0: "choke", 1: "unchoke", 2: "interested", 3: "not interested", 4: "have",
            5: "bitfield", 6: "request", 7: "piece", 8: "cancel", 9: "port",
            13: "suggest piece", 14: "have all", 15: "have none", 16: "reject request",
            17: "allowed fast", 20: "extended", 21: "hash request", 22: "hashes", 23: "hash reject"}
# 길이(ID 1바이트 포함)가 정해진 메시지. 짧으니 통째로 모아서 해석한다
FIXED = {0: 1, 1: 1, 2: 1, 3: 1, 4: 5, 6: 13, 8: 13, 9: 3, 13: 5, 14: 1, 15: 1, 16: 13, 17: 5}
# handshake reserved 비트: (바이트 위치, 비트, 이름) — BEP 10, BEP 6, BEP 5
RESERVED_BITS = ((5, 0x10, "Extension Protocol"), (7, 0x04, "Fast"), (7, 0x01, "DHT"))
# 경계를 잃었을 때 다시 맞출 머리: handshake, 16 KiB 블록 piece, request, have
PIECE_HEAD = b"\x00\x00\x40\x09\x07"              # 길이 16393(= 9 + 16 KiB) + ID 7
RESYNC = (HANDSHAKE_PREFIX, PIECE_HEAD, b"\x00\x00\x00\x0d\x06", b"\x00\x00\x00\x05\x04")
RESYNC_KEEP = max(len(p) for p in RESYNC) - 1     # 세그먼트 경계에 걸친 머리를 찾으려고 남길 끝 바이트
# peer_id 앞 "-XX0000-"(Azureus 방식)의 클라이언트 코드
CLIENTS = {"TR": "Transmission", "qB": "qBittorrent", "UT": "µTorrent", "LT": "libtorrent",
           "lt": "rTorrent", "DE": "Deluge", "AZ": "Vuze", "BI": "BiglyBT", "BT": "BitTorrent",
           "KT": "KTorrent", "BC": "BitComet", "WW": "WebTorrent"}
# 트래커 응답 bencode 사전에 나오는 키. 첫 키가 이 중 하나면 트래커 응답으로 본다
TRACKER_KEYS = frozenset({b"complete", b"crypto_flags", b"downloaded", b"external ip", b"failure reason",
                          b"files", b"flags", b"incomplete", b"interval", b"min interval", b"peers",
                          b"peers6", b"retry in", b"tracker id", b"warning message"})
# DHT 인자·응답에서 따로 보여 주는 키 (나머지는 이름만)
DHT_KEYS = frozenset({b"id", b"target", b"info_hash", b"port", b"implied_port", b"token", b"values",
                      b"nodes", b"nodes6", b"samples"})

_INT = re.compile(rb"0|-?[1-9][0-9]*")                     # bencode 정수: i03e, i-0e는 틀림
_HEX = re.compile(rb"[0-9A-Fa-f]{1,16}")                   # chunked 크기 줄
_REQUEST = re.compile(rb"GET (\S+) HTTP/1\.[01]")
_STATUS = re.compile(rb"HTTP/1\.[01] ([0-9]{3})(?: (.*))?")


def bdecode(data: bytes):
    """bencode bytes → int / bytes / list / dict(키는 bytes). 깨졌거나 값 뒤에 바이트가 남으면 ValueError."""
    value, end = _decode(data, 0, 0)
    if end != len(data):
        raise ValueError(f"bencode: 값이 끝난 뒤 {len(data) - end} bytes가 남음")
    return value


def parse_bt_tracker(data: bytes) -> Optional[AppInfo]:
    """트래커 요청(GET …?info_hash=…) 또는 응답(HTTP + bencode) → AppInfo(name="BT-TRACKER"), 아니면 None.

    None이면 parse_app()이 parse_http()로 넘긴다 (트래커가 아닌 HTTP).
    fields 키 (요청): is_request=True, kind("announce"/"scrape"), path, info_hash(첫 번째, 40자리 hex),
                    info_hashes, peer_id, client, event, params({이름: 값}), headers({host, user-agent})
    fields 키 (응답): is_request=False, kind, status_code, body_complete, interval, min_interval,
                    complete, incomplete, downloaded, peers(["IP:포트", …]), peer_count, failure_reason,
                    warning / scrape는 files({info_hash: {complete, downloaded, incomplete}})
    """
    if not data:
        return None
    head, body, complete = _split_http(data)
    first, _, rest = head.partition(b"\n")
    first = first.rstrip(b"\r")
    request = _REQUEST.fullmatch(first)
    if request:
        return _tracker_request(request.group(1), _headers(rest))
    status = _STATUS.fullmatch(first)
    if status and complete:
        return _tracker_response(int(status.group(1)), _text(status.group(2) or b""), _headers(rest), body)
    return None


def parse_bt_peer(conn_key: ConnKey, data: bytes) -> Optional[AppInfo]:
    """피어 연결 세그먼트 → AppInfo(name="BT-PEER").

    conn_key: 보내는 쪽 → 받는 쪽 순서의 (IP, 포트, IP, 포트). 메시지 경계는 방향마다 따로라서
              parse_app()이 방향 무관 키를 이렇게 돌려서 넘긴다
    fields 키: handshake({info_hash, peer_id, client, reserved, extensions} 또는 None),
              messages([{name, id, length, …}] — 이 세그먼트에서 시작한 메시지),
              continued(앞 세그먼트에서 시작한 메시지가 이 세그먼트에서 이어진 바이트), lost(경계를 잃음),
              gap(piece 도중 다음 piece 머리가 보임 = 캡처 손실이나 재전송)
    빈 데이터는 ValueError.
    """
    if not data:
        raise ValueError("BT-PEER: 빈 데이터")
    st = _flow(conn_key)
    peer = _flows.get(_reverse(conn_key))         # 반대 방향: 확장 메시지 ID는 받는 쪽이 정한다 (BEP 10)
    view, start = st.buf + data, len(st.buf)      # 앞 세그먼트에서 들고 온 바이트 + 이번 세그먼트
    st.buf = b""
    out = _Out()
    fields: dict = {"handshake": None, "messages": [], "continued": 0, "lost": False, "gap": False}
    pos = 0
    if st.left:
        pos = _continue(st, view, out, fields)
    elif st.lost:
        pos = _resync(st, view, 0, 0, start, out, fields)
    while pos < len(view):
        pos = _message(st, peer, view, pos, start, out, fields)
    return out.app("BT-PEER", fields)


def parse_bt_dht(data: bytes) -> Optional[AppInfo]:
    """UDP 페이로드(KRPC) → AppInfo(name="BT-DHT"). bencode 사전이지만 KRPC가 아니면 None, 깨졌으면 ValueError.

    fields 키: t(hex), y("q"/"r"/"e"), q(질의 이름), id(hex), items({키: 값} — 20바이트는 hex, 정수는 그대로,
              그 밖의 bytes는 길이), values·nodes(["IP:포트", …]), token_len, error([코드, 문구]),
              ip(BEP 42: 응답한 노드가 본 질의한 쪽 주소), v(클라이언트 버전)
    """
    if not data:
        raise ValueError("BT-DHT: 빈 데이터")
    msg = bdecode(data)
    if not isinstance(msg, dict):
        return None
    kind, tid = msg.get(b"y"), msg.get(b"t")
    if kind not in (b"q", b"r", b"e") or not isinstance(tid, bytes):
        return None                               # bencode 사전이지만 KRPC가 아님
    t = tid.hex()
    out = _Out()
    fields: dict = {"t": t, "y": kind.decode(), "q": None, "id": None, "items": {}, "values": [],
                    "nodes": [], "token_len": None, "error": None, "ip": None, "v": None}
    if kind == b"q":
        q = msg.get(b"q")
        fields["q"] = _text(q) if isinstance(q, bytes) else None
        out.add(_show(f"query {fields['q'] or '?'} t={t}"))
        body = msg.get(b"a")
    elif kind == b"r":
        out.add(f"response t={t}")
        body = msg.get(b"r")
    else:
        err = msg.get(b"e")
        code = err[0] if isinstance(err, list) and err and isinstance(err[0], int) else None
        text = _text(err[1]) if isinstance(err, list) and len(err) > 1 and isinstance(err[1], bytes) else ""
        fields["error"] = [code, text]
        out.add(_show(f"error {code}" + (f" {text}" if text else "") + f" t={t}"))
        body = None
    if isinstance(body, dict):
        _dht_body(body, out, fields)
    ip = msg.get(b"ip")
    if isinstance(ip, bytes) and len(ip) in (6, 18):
        fields["ip"] = _addr(ip)
        out.add(f"ip: {fields['ip']} (응답한 노드가 본 질의한 쪽 주소)")
    v = msg.get(b"v")
    if isinstance(v, bytes) and v:
        fields["v"] = _version(v)
        out.add(f"v: {fields['v']}")
    return out.app("BT-DHT", fields)


def reset_state() -> None:
    """기억한 피어 연결 상태를 모두 지운다 (테스트용)."""
    _flows.clear()


# -----------------------------------------------------------------------------
# bencode
# -----------------------------------------------------------------------------
def _decode(data: bytes, pos: int, depth: int):
    """data[pos]에서 시작하는 값 하나 → (값, 값 뒤 위치)."""
    if pos >= len(data):
        raise ValueError("bencode: 값이 끝나기 전에 데이터가 끝남")
    c = data[pos]
    if c == 0x69:                                 # i…e 정수
        end = data.find(b"e", pos + 1, pos + 2 + MAX_DIGITS)
        if end < 0 or not _INT.fullmatch(data, pos + 1, end):
            raise ValueError("bencode: 정수 형식이 틀림")
        return int(data[pos + 1:end]), end + 1
    if c in (0x6C, 0x64):                         # l…e 리스트, d…e 사전
        if depth >= MAX_DEPTH:
            raise ValueError("bencode: 중첩이 너무 깊음")
        pos += 1
        if c == 0x6C:
            items = []
            while True:
                if pos >= len(data):
                    raise ValueError("bencode: 리스트가 끝나지 않음")
                if data[pos] == 0x65:
                    return items, pos + 1
                item, pos = _decode(data, pos, depth + 1)
                items.append(item)
        result: dict = {}
        while True:
            if pos >= len(data):
                raise ValueError("bencode: 사전이 끝나지 않음")
            if data[pos] == 0x65:
                return result, pos + 1
            key, pos = _string(data, pos)         # 사전 키는 문자열만
            result[key], pos = _decode(data, pos, depth + 1)
    if 0x30 <= c <= 0x39:
        return _string(data, pos)
    raise ValueError(f"bencode: 값이 0x{c:02x}로 시작함")


def _string(data: bytes, pos: int) -> tuple[bytes, int]:
    """길이:값 문자열 → (값, 값 뒤 위치)."""
    colon = data.find(b":", pos, pos + 12)
    digits = data[pos:colon] if colon > pos else b""
    if not digits.isdigit():
        raise ValueError("bencode: 문자열 길이 형식이 틀림")
    end = colon + 1 + int(digits)
    if end > len(data):
        raise ValueError("bencode: 문자열이 데이터보다 김")
    return data[colon + 1:end], end


def _dict_prefix(data: bytes) -> tuple[dict, bool]:
    """bencode 사전을 앞에서부터 읽을 수 있는 데까지 → (사전, 끝까지 읽었는지). 본문이 잘린 트래커 응답용."""
    result: dict = {}
    pos = 1
    try:
        while pos < len(data):
            if data[pos] == 0x65:
                return result, True
            key, pos = _string(data, pos)
            result[key], pos = _decode(data, pos, 1)
    except ValueError:
        pass
    return result, False


# -----------------------------------------------------------------------------
# 트래커 (HTTP)
# -----------------------------------------------------------------------------
def _split_http(data: bytes) -> tuple[bytes, bytes, bool]:
    """(헤더 부분, 본문, 헤더 끝 빈 줄을 찾았는지)."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        end = data.find(sep)
        if end >= 0:
            return data[:end], data[end + len(sep):], True
    return data, b"", False


def _headers(raw: bytes) -> dict[str, str]:
    """헤더 줄 → {소문자 이름: 값}. 같은 이름이 또 오면 처음 것."""
    headers: dict[str, str] = {}
    for line in raw.split(b"\n")[:64]:
        name, colon, value = line.rstrip(b"\r").partition(b":")
        if colon and name.strip():
            headers.setdefault(name.strip().decode("latin-1").lower(), _text(value.strip()))
    return headers


def _query(query: bytes) -> dict[str, list[bytes]]:
    """URL 쿼리 → {이름: [값(퍼센트 디코딩한 bytes), …]}. info_hash·peer_id는 아무 바이트나 될 수 있다."""
    params: dict[str, list[bytes]] = {}
    for part in query.split(b"&")[:MAX_PARAMS]:
        if part:
            name, _, value = part.partition(b"=")
            params.setdefault(unquote_to_bytes(name).decode("latin-1"), []).append(unquote_to_bytes(value))
    return params


def _tracker_request(target: bytes, headers: dict[str, str]) -> Optional[AppInfo]:
    if target[:8].lower().startswith((b"http://", b"https://")):     # 프록시 방식: GET http://트래커/announce?…
        slash = target.find(b"/", target.find(b"//") + 2)
        target = target[slash:] if slash >= 0 else b"/"
    path, _, query = target.partition(b"?")
    params = _query(query)
    hashes = params.pop("info_hash", [])
    if not hashes:
        return None                               # info_hash가 없으면 트래커 요청이 아님 → HTTP
    kind = "scrape" if path.rsplit(b"/", 1)[-1].lower().startswith(b"scrape") else "announce"
    peer_id = params.pop("peer_id", [None])[0]
    values = {name: _text(vals[0]) for name, vals in params.items()}
    event = values.get("event", "")
    client = _client(peer_id) if peer_id is not None else None
    fields = {"is_request": True, "kind": kind, "path": _text(path), "info_hash": hashes[0].hex(),
              "info_hashes": [h.hex() for h in hashes[:MAX_KEEP]],
              "peer_id": None if peer_id is None else _bytes_text(peer_id), "client": client,
              "event": event or None, "params": values,
              "headers": {name: headers[name] for name in ("host", "user-agent") if name in headers}}
    out = _Out()
    if kind == "scrape":
        out.add(f"scrape 요청 (info_hash {len(hashes)}개)")
    else:
        out.add("announce 요청" + (_show(f" (event={event})") if event else ""))
    for h in hashes[:MAX_PEERS]:
        out.add(f"info_hash: {_hash_text(h)}")
    if len(hashes) > MAX_PEERS:
        out.add(f"… info_hash {len(hashes) - MAX_PEERS}개 더")
    if peer_id is not None:
        out.add(f"peer_id: {_bytes_text(peer_id)}" + (f" ({client})" if client else ""))
    for group in (("port",), ("uploaded", "downloaded", "left"), ("compact", "numwant")):
        shown = [f"{name}: {values[name]}" for name in group if name in values]
        if shown:
            out.add(_show(", ".join(shown)))
    for name, title in (("host", "Host"), ("user-agent", "User-Agent")):
        if name in headers:
            out.add(_show(f"{title}: {headers[name]}"))
    return out.app("BT-TRACKER", fields)


def _tracker_response(code: int, reason: str, headers: dict[str, str], body: bytes) -> Optional[AppInfo]:
    peek = _http_body(headers, body, 32)          # 트래커 응답인지 앞부분만 풀어 본다 (일반 웹 페이지가 많으므로)
    if peek[:1] != b"d":
        return None
    try:
        first_key, _ = _string(peek, 1)
    except ValueError:
        return None
    if first_key not in TRACKER_KEYS:
        return None                               # 트래커 응답 모양이 아님 → HTTP
    d, whole = _dict_prefix(_http_body(headers, body, MAX_BODY))
    status = _show(f"{code} {reason}".rstrip())
    out = _Out()
    fields: dict = {"is_request": False, "status_code": code, "body_complete": whole}
    if first_key == b"files" or b"files" in d:
        _scrape_reply(d, status, out, fields)
    else:
        _announce_reply(d, status, out, fields)
    if not whole:
        out.add("(bencode 본문이 다음 세그먼트로 이어짐: 읽은 데까지만 표시)")
    return out.app("BT-TRACKER", fields)


def _announce_reply(d: dict, status: str, out: _Out, fields: dict) -> None:
    num = {key: d[key] for key in (b"interval", b"min interval", b"complete", b"incomplete", b"downloaded")
           if isinstance(d.get(key), int)}
    failure, warning = d.get(b"failure reason"), d.get(b"warning message")
    peers, form, count = _peers(d.get(b"peers"))
    peers6, form6, count6 = _peers6(d.get(b"peers6"))
    fields.update(kind="announce", interval=num.get(b"interval"), min_interval=num.get(b"min interval"),
                  complete=num.get(b"complete"), incomplete=num.get(b"incomplete"),
                  downloaded=num.get(b"downloaded"), peers=(peers + peers6)[:MAX_KEEP],
                  peer_count=count + count6,
                  failure_reason=_text(failure) if isinstance(failure, bytes) else None,
                  warning=_text(warning) if isinstance(warning, bytes) else None)
    if fields["failure_reason"] is not None:
        out.add(_show(f"announce 응답 {status}: 실패 - {fields['failure_reason']}"))
    else:
        out.add(f"announce 응답 {status}" + (f", peers {count + count6}개" if form or form6 else ""))
    if b"interval" in num:
        least = f" (min interval: {num[b'min interval']}초)" if b"min interval" in num else ""
        out.add(f"interval: {num[b'interval']}초{least}")
    counts = [f"{key.decode()}: {num[key]} ({note})" for key, note in
              ((b"complete", "시드"), (b"incomplete", "받는 중"), (b"downloaded", "다 받은 횟수")) if key in num]
    if counts:
        out.add(", ".join(counts))
    if fields["warning"] is not None:
        out.add(_show(f"warning message: {fields['warning']}"))
    _peer_lines("peers", peers, form, count, out)
    _peer_lines("peers6", peers6, form6, count6, out)


def _scrape_reply(d: dict, status: str, out: _Out, fields: dict) -> None:
    files = d.get(b"files") if isinstance(d.get(b"files"), dict) else {}
    stats = {}
    for info_hash, numbers in list(files.items())[:MAX_KEEP]:
        if isinstance(numbers, dict):
            stats[info_hash.hex()] = {key.decode("latin-1"): value for key, value in numbers.items()
                                      if key in (b"complete", b"downloaded", b"incomplete") and isinstance(value, int)}
    fields.update(kind="scrape", files=stats)
    out.add(f"scrape 응답 {status}, 파일 {len(files)}개")
    for info_hash, numbers in list(stats.items())[:MAX_PEERS]:
        out.add(f"{info_hash}: " + ", ".join(f"{key}={value}" for key, value in numbers.items()))
    if len(files) > MAX_PEERS:
        out.add(f"… 파일 {len(files) - MAX_PEERS}개 더")


def _peers(value) -> tuple[list[str], Optional[str], int]:
    """트래커 응답 peers → (["IP:포트", …] MAX_KEEP개까지, 형식, 전체 수). 없으면 ([], None, 0)."""
    if isinstance(value, bytes):                  # compact (BEP 23): IPv4 4바이트 + 포트 2바이트씩
        count = len(value) // 6
        return [_addr(value[i:i + 6]) for i in range(0, min(count, MAX_KEEP) * 6, 6)], "compact", count
    if isinstance(value, list):                   # 사전 목록 (BEP 3): {ip, port, peer id}
        peers = [_host_port(_text(p[b"ip"]), p[b"port"]) for p in value
                 if isinstance(p, dict) and isinstance(p.get(b"ip"), bytes) and isinstance(p.get(b"port"), int)]
        return peers[:MAX_KEEP], "사전 목록", len(peers)
    return [], None, 0


def _host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"      # IPv6 주소는 괄호로


def _peers6(value) -> tuple[list[str], Optional[str], int]:
    """peers6 (BEP 7): IPv6 16바이트 + 포트 2바이트씩."""
    if not isinstance(value, bytes):
        return [], None, 0
    count = len(value) // 18
    return [_addr(value[i:i + 18]) for i in range(0, min(count, MAX_KEEP) * 18, 18)], "compact", count


def _peer_lines(title: str, peers: list[str], form: Optional[str], count: int, out: _Out) -> None:
    if form is None:
        return
    out.add(f"{title} {count}개 ({form})")
    for peer in peers[:MAX_PEERS]:
        out.add(NEST + _show(peer))
    if count > MAX_PEERS:
        out.add(NEST + f"… {count - MAX_PEERS}개 더")


def _http_body(headers: dict[str, str], body: bytes, limit: int) -> bytes:
    """chunked·gzip·deflate 본문을 limit 바이트까지 푼다. 풀 수 없으면 b""."""
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    encoding = headers.get("content-encoding", "").strip().lower()
    if encoding in ("gzip", "x-gzip", "deflate"):
        for wbits in (47, -15):                   # 47: zlib·gzip 머리를 알아서, -15: 머리 없는 deflate
            try:
                return zlib.decompressobj(wbits).decompress(body, limit)
            except zlib.error:
                pass
        return b""
    return body[:limit]


def _dechunk(body: bytes) -> bytes:
    """chunked 본문에서 데이터만 (이 세그먼트에 있는 만큼, MAX_BODY까지)."""
    parts, pos, total = [], 0, 0
    while pos < len(body) and total < MAX_BODY:
        nl = body.find(b"\n", pos, pos + 64)
        size = body[pos:nl].split(b";")[0].strip() if nl >= 0 else b""
        if not _HEX.fullmatch(size) or int(size, 16) == 0:
            break
        chunk = body[nl + 1:nl + 1 + int(size, 16)]
        parts.append(chunk)
        total += len(chunk)
        pos = nl + 1 + int(size, 16) + 2          # 데이터 뒤 CRLF
    return b"".join(parts)[:MAX_BODY]


# -----------------------------------------------------------------------------
# 피어 연결 (방향별 메시지 흐름)
# -----------------------------------------------------------------------------
class _Flow:
    """피어 연결의 한 방향(보내는 쪽 → 받는 쪽) 메시지 흐름."""

    def __init__(self):
        self.buf = b""            # 아직 해석하지 못한 앞부분: 잘린 handshake·메시지 머리 (경계를 잃었으면 끝 몇 바이트)
        self.left = 0             # 지금 메시지에서 아직 오지 않은 바이트 (본문을 세며 건너뛰는 중)
        self.what = ""            # 건너뛰는 메시지 (화면용, 예: "piece index=3 begin=16384")
        self.mid: Optional[int] = None    # 건너뛰는 메시지 ID
        self.total = 0            # 그 메시지 본문 크기 (piece는 블록 크기)
        self.bits = 0             # bitfield: 지금까지 센 1 비트 = 가진 조각 수
        self.lost = False         # 메시지 경계를 잃음
        self.ext: dict[int, str] = {}     # 이쪽이 보낸 확장 handshake의 m: 이쪽으로 보낼 때 쓰는 ID → 이름


_flows: OrderedDict[ConnKey, _Flow] = OrderedDict()


def _flow(key: ConnKey) -> _Flow:
    st = _flows.get(key)
    if st is None:
        st = _flows[key] = _Flow()
        if len(_flows) > MAX_FLOWS:
            _flows.popitem(last=False)            # 가장 오래 안 쓴 방향
    else:
        _flows.move_to_end(key)
    return st


def _reverse(key: ConnKey) -> ConnKey:
    return (key[2], key[3], key[0], key[1])


def _message(st: _Flow, peer: Optional[_Flow], view: bytes, pos: int, start: int,
             out: _Out, fields: dict) -> int:
    """view[pos]에서 시작하는 handshake·메시지 하나를 해석하고 그 뒤 위치를 돌려준다."""
    rest = len(view) - pos
    if view[pos:pos + 20] == HANDSHAKE_PREFIX[:rest]:      # handshake (또는 그 앞부분)
        if rest < HANDSHAKE_LEN:
            return _wait(st, view, pos, out, f"handshake가 다음 세그먼트로 이어짐: {rest}/{HANDSHAKE_LEN} bytes")
        _handshake(st, view[pos:pos + HANDSHAKE_LEN], out, fields)
        return pos + HANDSHAKE_LEN
    if rest < 4:
        return _wait(st, view, pos, out, f"메시지 머리가 다음 세그먼트로 이어짐: {rest}/4 bytes")
    length = int.from_bytes(view[pos:pos + 4], "big")
    if length == 0:
        if view[pos + 4:pos + 8] == b"\x00\x00\x00\x00":   # keep-alive는 연달아 오지 않는다 → 0으로 찬 데이터
            return _resync(st, view, pos, pos + 1, start, out, fields)
        out.add("keep-alive")
        fields["messages"].append({"name": "keep-alive", "id": None, "length": 0})
        return pos + 4
    if rest < 5:
        return _wait(st, view, pos, out, f"메시지 머리가 다음 세그먼트로 이어짐: {rest}/5 bytes")
    mid = view[pos + 4]
    if not _valid(length, mid):
        return _resync(st, view, pos, pos + 1, start, out, fields)
    need = _need(view, pos, length, mid)
    if rest < need:
        return _wait(st, view, pos, out, f"메시지 머리가 다음 세그먼트로 이어짐: {rest}/{need} bytes")
    return _describe(st, peer, view, pos, length, mid, out, fields)


def _valid(length: int, mid: int) -> bool:
    """메시지 길이(ID 포함)와 ID가 말이 되는지. 아니면 메시지 경계를 잃은 것."""
    if mid not in MESSAGES or length > MAX_MESSAGE:
        return False
    if mid in FIXED:
        return length == FIXED[mid]
    if mid == 7:
        return 9 <= length <= 9 + MAX_BLOCK
    return length >= 2 if mid == 20 else length >= 1


def _need(view: bytes, pos: int, length: int, mid: int) -> int:
    """이 메시지를 해석하려면 메시지 앞에서부터 있어야 하는 바이트 수."""
    if mid in FIXED:
        return 4 + length                         # 짧은 메시지는 통째로
    if mid == 7:
        return 13                                 # 길이·ID·index·begin
    if mid == 20:
        if len(view) - pos < 6:
            return 6                              # 확장 메시지 ID까지
        if view[pos + 5] == 0 and length <= MAX_EXTENDED:
            return 4 + length                     # 작은 확장 handshake는 통째로 (bencode를 본다)
        return 6
    return 5


def _wait(st: _Flow, view: bytes, pos: int, out: _Out, text: str) -> int:
    """잘린 앞부분을 들고 있다가 다음 세그먼트 앞에 붙여 해석한다."""
    st.buf = view[pos:]
    out.add(f"({text})")
    return len(view)


def _resync(st: _Flow, view: bytes, pos: int, search: int, start: int, out: _Out, fields: dict) -> int:
    """메시지 경계를 잃음: 다시 맞출 머리(RESYNC)를 view[search:]에서 찾아 그 위치를, 못 찾으면 끝을 돌려준다."""
    fields["lost"] = True
    hits = [i for i in (view.find(p, search) for p in RESYNC) if i >= 0]
    lost_from = max(pos, start)                   # 이번 세그먼트의 바이트만 센다 (앞에서 들고 온 바이트 빼고)
    if hits:
        found = min(hits)
        st.lost = False
        skipped = max(found - lost_from, 0)
        out.add(f"(메시지 경계를 잃음: {skipped} bytes 건너뛰고 다시 맞춤)" if skipped else "(메시지 경계를 다시 맞춤)")
        return found
    st.lost = True
    st.buf = view[-RESYNC_KEEP:]                  # 다음 세그먼트에 걸친 머리도 찾도록 끝 몇 바이트를 남긴다
    out.add(f"(메시지 경계를 잃음: {len(view) - lost_from} bytes)")
    return len(view)


def _handshake(st: _Flow, raw: bytes, out: _Out, fields: dict) -> None:
    reserved, info_hash, peer_id = raw[20:28], raw[28:48], raw[48:68]
    st.ext = {}                                   # 새 연결 (같은 주소·포트를 다시 쓴 경우도)
    exts = [name for i, bit, name in RESERVED_BITS if reserved[i] & bit]
    client = _client(peer_id)
    fields["handshake"] = {"info_hash": info_hash.hex(), "peer_id": _bytes_text(peer_id), "client": client,
                           "reserved": reserved.hex(), "extensions": exts}
    fields["messages"].append({"name": "handshake", "id": None, "length": HANDSHAKE_LEN})
    out.add("handshake")
    out.add(NEST + f"info_hash: {info_hash.hex()}")
    out.add(NEST + f"peer_id: {_bytes_text(peer_id)}" + (f" ({client})" if client else ""))
    out.add(NEST + f"reserved: {reserved.hex()}" + (f" ({', '.join(exts)})" if exts else ""))


def _describe(st: _Flow, peer: Optional[_Flow], view: bytes, pos: int, length: int, mid: int,
              out: _Out, fields: dict) -> int:
    """머리를 다 모은 메시지 하나 → 화면 줄. 본문이 이 세그먼트 밖으로 이어지면 남은 바이트를 기억."""
    name = MESSAGES[mid]
    end = pos + 4 + length                        # 메시지 끝 (이 세그먼트 밖일 수 있음)
    body = pos + 5                                # ID 뒤
    info: dict = {"name": name, "id": mid, "length": length}
    fields["messages"].append(info)
    if mid in (4, 13, 17):                        # have, suggest piece, allowed fast: 조각 번호
        info["index"] = int.from_bytes(view[body:body + 4], "big")
        out.add(f"{name} index={info['index']}")
        return end
    if mid in (6, 8, 16):                         # request, cancel, reject request
        info["index"], info["begin"], info["block"] = struct.unpack_from("!III", view, body)
        out.add(f"{name} index={info['index']} begin={info['begin']} length={info['block']}")
        return end
    if mid == 9:                                  # port: DHT 포트 (BEP 5)
        info["port"] = int.from_bytes(view[body:body + 2], "big")
        out.add(f"port {info['port']} (DHT 포트)")
        return end
    if mid in FIXED:                              # choke, unchoke, interested, not interested, have all, have none
        out.add(name)
        return end
    if mid == 20 and view[body] == 0 and length <= MAX_EXTENDED:
        _extended_handshake(st, view[body + 1:end], out, info)
        return end
    # 본문이 길 수 있는 메시지 (piece, bitfield, extended, v2 해시): 본문은 크기만 세며 건너뛴다
    if mid == 7:
        info["index"], info["begin"] = struct.unpack_from("!II", view, body)
        info["block"] = length - 9
        what, skip = f"piece index={info['index']} begin={info['begin']}", body + 8
        out.add(f"{what} block={info['block']} bytes")
    elif mid == 20:
        ext_id = view[body]
        ext_name = peer.ext.get(ext_id) if peer is not None else None
        info.update(ext_id=ext_id, ext_name=ext_name)
        label = "handshake" if ext_id == 0 else ext_name or f"id={ext_id}"
        what, skip = _show(f"extended {label}"), body + 1
        out.add(f"{what} {length - 2} bytes")
    else:                                         # bitfield, hash request·hashes·hash reject
        what, skip = name, body
        out.add(f"{name} {length - 1} bytes")
    total, got = end - skip, min(end, len(view)) - skip
    bits = _ones(view[skip:skip + got]) if mid == 5 else 0
    if end <= len(view):
        if mid == 5:
            info["pieces"] = bits
            out.items[-1] += f", 가진 조각 {bits}개"
        return end
    st.left, st.what, st.mid, st.total, st.bits = end - len(view), what, mid, total, bits
    out.add(NEST + f"(다음 세그먼트로 이어짐: {got}/{total} bytes)")
    return len(view)


def _continue(st: _Flow, view: bytes, out: _Out, fields: dict) -> int:
    """앞 세그먼트에서 시작한 메시지 본문이 이어짐: 크기만 센다."""
    take = min(st.left, len(view))
    if st.mid == 7:                               # piece가 끝나기 전에 다음 piece 머리 = 캡처 손실이나 재전송
        early = view.find(PIECE_HEAD, 0, take + len(PIECE_HEAD) - 1)
        if 0 <= early < take:
            got = st.total - st.left + early
            st.left = 0
            fields["continued"], fields["gap"] = early, True
            out.add(f"{st.what} 이어짐 {early} bytes ({got}/{st.total}에서 끊김: 캡처 손실·재전송)")
            return early
    if st.mid == 5:
        st.bits += _ones(view[:take])
    st.left -= take
    fields["continued"] = take
    got = st.total - st.left
    if st.left:
        out.add(f"{st.what} 이어짐 {take} bytes ({got}/{st.total})")
    else:
        pieces = f", 가진 조각 {st.bits}개" if st.mid == 5 else ""
        out.add(f"{st.what} 이어짐 {take} bytes ({got}/{st.total} 끝){pieces}")
    return take


def _extended_handshake(st: _Flow, payload: bytes, out: _Out, info: dict) -> None:
    """확장 handshake (BEP 10): bencode 사전의 v(클라이언트)·p(포트)·m(확장 이름 → ID) 등."""
    info["ext_id"] = 0
    try:
        d = bdecode(payload)
    except ValueError:
        d = None
    if not isinstance(d, dict):
        out.add(f"extended handshake {len(payload)} bytes (bencode 사전이 아님)")
        return
    out.add("extended handshake")
    v = d.get(b"v")
    if isinstance(v, bytes):
        info["v"] = _text(v)
        out.add(NEST + _show(f"v: {info['v']}"))
    if isinstance(d.get(b"p"), int):
        info["p"] = d[b"p"]
        out.add(NEST + f"p: {info['p']}")
    m = d.get(b"m")
    if isinstance(m, dict):
        st.ext = {}
        for key, ext_id in m.items():
            if isinstance(ext_id, int) and 0 < ext_id < 256 and len(st.ext) < MAX_EXT_NAMES:
                st.ext[ext_id] = _text(key)       # 0은 "이 확장을 끔"
        info["m"] = {ext_name: ext_id for ext_id, ext_name in st.ext.items()}
        if st.ext:
            out.add(NEST + _show("m: " + ", ".join(f"{n}={i}" for i, n in sorted(st.ext.items()))))
    for key in (b"metadata_size", b"reqq"):
        if isinstance(d.get(key), int):
            info[key.decode()] = d[key]
            out.add(NEST + f"{key.decode()}: {d[key]}")
    yourip = d.get(b"yourip")
    if isinstance(yourip, bytes) and len(yourip) in (4, 16):
        info["yourip"] = str(ipaddress.ip_address(yourip))
        out.add(NEST + f"yourip: {info['yourip']}")


def _ones(raw: bytes) -> int:
    """1인 비트 수 (bitfield에서 가진 조각 수)."""
    return bin(int.from_bytes(raw, "big")).count("1") if raw else 0


# -----------------------------------------------------------------------------
# DHT
# -----------------------------------------------------------------------------
def _dht_body(body: dict, out: _Out, fields: dict) -> None:
    """질의 인자(a)·응답(r) 사전 → 줄. id·target·info_hash는 hex, nodes·values는 주소, token은 길이."""
    for key, value in body.items():
        if isinstance(value, bytes):
            fields["items"][_text(key)] = value.hex() if len(value) == 20 else len(value)
        elif isinstance(value, int):
            fields["items"][_text(key)] = value
    for key in (b"id", b"target", b"info_hash"):
        value = body.get(key)
        if isinstance(value, bytes):
            if key == b"id":
                fields["id"] = value.hex()
            out.add(f"{key.decode()}: {_hash_text(value)}")
    port = body.get(b"port")
    if isinstance(port, int):
        implied = " (implied_port=1: 보낸 UDP 포트를 쓰라는 뜻)" if body.get(b"implied_port") == 1 else ""
        out.add(f"port: {port}{implied}")
    token = body.get(b"token")
    if isinstance(token, bytes):
        fields["token_len"] = len(token)
        out.add(f"token: {len(token)} bytes")
    values = body.get(b"values")
    if isinstance(values, list):
        peers = [_addr(v) for v in values if isinstance(v, bytes) and len(v) in (6, 18)]
        fields["values"] = peers[:MAX_KEEP]
        out.add(_addr_line("values", peers))
    for key, size in ((b"nodes", 26), (b"nodes6", 38)):           # 노드 ID 20바이트 + 주소
        raw = body.get(key)
        if isinstance(raw, bytes):
            nodes = [_addr(raw[i + 20:i + size]) for i in range(0, len(raw) - size + 1, size)]
            if key == b"nodes":
                fields["nodes"] = nodes[:MAX_KEEP]
            out.add(_addr_line(key.decode(), nodes))
    samples = body.get(b"samples")
    if isinstance(samples, bytes):
        out.add(f"samples {len(samples) // 20}개")
    other = [_text(key) for key in body if key not in DHT_KEYS]
    if other:
        out.add(_show("그 밖의 키: " + ", ".join(other)))


def _addr_line(title: str, addrs: list[str]) -> str:
    more = ", …" if len(addrs) > MAX_ADDRS else ""
    return f"{title} {len(addrs)}개" + (": " + ", ".join(addrs[:MAX_ADDRS]) + more if addrs else "")


def _version(v: bytes) -> str:
    """DHT v(클라이언트 버전): 보통 클라이언트 코드 2글자 + 버전 2바이트."""
    if len(v) == 4 and v[:2].isalpha():
        return f"{v[:2].decode('latin-1')} {v[2:].hex()}"
    return _bytes_text(v)


# -----------------------------------------------------------------------------
# 공통 도우미
# -----------------------------------------------------------------------------
class _Out:
    """세그먼트 하나의 화면 줄을 모은다."""

    def __init__(self):
        self.items: list[str] = []

    def add(self, text: str) -> None:
        self.items.append(text)

    def app(self, name: str, fields: dict) -> AppInfo:
        items = self.items or ["(내용 없음)"]
        if len(items) > MAX_ITEMS:
            items = items[:MAX_ITEMS] + [f"… {len(items) - MAX_ITEMS}줄 더 (모두 {len(items)}줄)"]
        return AppInfo(name=name, summary=items[0], lines=items[1:], fields=fields)


def _addr(raw: bytes) -> str:
    """compact 주소 (IPv4 4바이트 또는 IPv6 16바이트 + 포트 2바이트) → "IP:포트"."""
    return _host_port(str(ipaddress.ip_address(raw[:-2])), int.from_bytes(raw[-2:], "big"))


def _client(peer_id: bytes) -> Optional[str]:
    """peer_id "-TR4060-…"(Azureus 방식) → 클라이언트 이름. 모르면 None."""
    if len(peer_id) >= 8 and peer_id[:1] == b"-" and peer_id[7:8] == b"-":
        return CLIENTS.get(peer_id[1:3].decode("latin-1"))
    return None


def _hash_text(h: bytes) -> str:
    return h.hex() if len(h) == 20 else f"{h.hex()} ({len(h)} bytes)"


def _bytes_text(raw: bytes) -> str:
    """바이트를 그대로 보여 줄 때(peer_id 등): 출력할 수 있는 ASCII는 그대로, 나머지는 \\xNN."""
    return "".join(chr(b) if 0x20 <= b < 0x7F else f"\\x{b:02x}" for b in raw)


def _text(raw: bytes) -> str:
    """UTF-8이 아닌 바이트는 �로."""
    return raw.decode("utf-8", errors="replace")


def _show(text: str) -> str:
    """화면용: 제어 문자(터미널 색·커서를 바꿀 수 있음, C1 포함)는 \\xNN으로, 너무 길면 … 로 자른다."""
    safe = "".join(ch if ch == "\t" or not (ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F)
                   else f"\\x{ord(ch):02x}" for ch in text)
    return safe if len(safe) <= MAX_SHOW else safe[:MAX_SHOW] + "…"
