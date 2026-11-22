# =============================================================================
# BitTorrent 해석(bdecode·parse_bt_tracker·parse_bt_peer·parse_bt_dht) 단위 테스트 (#17)
# - 실제 클라이언트 트래픽은 시연 때 확인 → 여기는 BEP 3·5·6·10·23 형식대로 만든 bytes
#   (DHT는 BEP 5 문서에 있는 예 그대로, 트래커 요청은 Transmission 4.0이 보내는 모양)
# - 세그먼트를 걸친 piece·bitfield·handshake, 잘린 머리, 경계를 잃었다가 다시 맞춤, 방향별 경계
# - parse_app 분기(실제 파서) → decode() → format_packet 화면 줄
# =============================================================================
import contextlib
import gzip
import io
import ipaddress
import socket
import struct
import unittest
import zlib
from urllib.parse import quote_from_bytes

from src.decode import app_bt, app_select
from src.decode.app_bt import (MAX_EXTENDED, MAX_FLOWS, MAX_ITEMS, MAX_PEERS, bdecode, parse_bt_dht,
                               parse_bt_peer, parse_bt_tracker)
from src.decode.app_select import parse_app
from src.models import DEFAULT_PORTS, Captured, canonical_key
from tests.test_link_ip import eth, ipv4, tcp_header


def benc(obj) -> bytes:
    """테스트용 bencode 인코더 (사전 키는 정렬)."""
    if isinstance(obj, int):
        return b"i%de" % obj
    if isinstance(obj, bytes):
        return b"%d:%s" % (len(obj), obj)
    if isinstance(obj, list):
        return b"l" + b"".join(benc(x) for x in obj) + b"e"
    if isinstance(obj, dict):
        return b"d" + b"".join(benc(k) + benc(v) for k, v in sorted(obj.items())) + b"e"
    raise TypeError(obj)


def msg(mid: int, payload: bytes = b"") -> bytes:
    """피어 메시지: 4바이트 길이(ID 포함) + ID + 본문."""
    return struct.pack("!IB", 1 + len(payload), mid) + payload


def compact(peers) -> bytes:
    return b"".join(socket.inet_aton(ip) + struct.pack("!H", port) for ip, port in peers)


def screen(app):
    return [app.summary] + app.lines


# ---- 피어
A2B = ("192.0.2.1", 51413, "198.51.100.2", 6881)       # 보내는 쪽 → 받는 쪽 (parse_app이 돌려서 넘기는 키)
B2A = ("198.51.100.2", 6881, "192.0.2.1", 51413)
INFO_HASH = bytes.fromhex("0123456789abcdef0123456789abcdef01234567")
PEER_ID = b"-TR4060-k8hj0wgej6ch"
RESERVED = bytes.fromhex("0000000000100005")           # 확장 메시지(BEP 10) + Fast(BEP 6) + DHT(BEP 5)
HANDSHAKE = b"\x13BitTorrent protocol" + RESERVED + INFO_HASH + PEER_ID
HANDSHAKE_B = b"\x13BitTorrent protocol" + bytes(8) + INFO_HASH + b"-qB4630-abcdefghijkl"
HANDSHAKE_SCREEN = ["handshake",
                    "  info_hash: 0123456789abcdef0123456789abcdef01234567",
                    "  peer_id: -TR4060-k8hj0wgej6ch (Transmission)",
                    "  reserved: 0000000000100005 (Extension Protocol, Fast, DHT)"]
EXT_HANDSHAKE = msg(20, b"\x00" + benc({b"m": {b"ut_metadata": 3, b"ut_pex": 1, b"lt_donthave": 0},
                                        b"metadata_size": 31277, b"p": 51413, b"reqq": 512,
                                        b"v": b"Transmission 4.0.6",
                                        b"yourip": socket.inet_aton("203.0.113.7")}))
EXT_SCREEN = ["extended handshake", "  v: Transmission 4.0.6", "  p: 51413", "  m: ut_pex=1, ut_metadata=3",
              "  metadata_size: 31277", "  reqq: 512", "  yourip: 203.0.113.7"]
BLOCK = bytes(range(256)) * 64                         # 16 KiB 블록
PIECE = msg(7, struct.pack("!II", 3, 16384) + BLOCK)   # 16397 bytes
SMALL = (b"\x00\x00\x00\x00" + msg(0) + msg(1) + msg(2) + msg(3) + msg(4, struct.pack("!I", 7))
         + msg(6, struct.pack("!III", 7, 16384, 16384)) + msg(8, struct.pack("!III", 7, 16384, 16384))
         + msg(9, struct.pack("!H", 51413)) + msg(13, struct.pack("!I", 8)) + msg(14) + msg(15)
         + msg(16, struct.pack("!III", 7, 0, 16384)) + msg(17, struct.pack("!I", 9)))
SMALL_SCREEN = ["keep-alive", "choke", "unchoke", "interested", "not interested", "have index=7",
                "request index=7 begin=16384 length=16384", "cancel index=7 begin=16384 length=16384",
                "port 51413 (DHT 포트)", "suggest piece index=8", "have all", "have none",
                "reject request index=7 begin=0 length=16384", "allowed fast index=9"]

# ---- 트래커: Transmission 4.0이 보내는 announce 모양 (info_hash는 퍼센트 인코딩한 20바이트)
ANNOUNCE = (b"GET /announce?info_hash=%01%23Eg%89%AB%CD%EF%01%23Eg%89%AB%CD%EF%01%23Eg"
            b"&peer_id=-TR4060-k8hj0wgej6ch&port=51413&uploaded=0&downloaded=0&left=6114656256"
            b"&numwant=80&key=6e2b1a3f&compact=1&supportcrypto=1&event=started HTTP/1.1\r\n"
            b"Host: tracker.test.local:6969\r\nUser-Agent: Transmission/4.0.6\r\nAccept: */*\r\n"
            b"Accept-Encoding: deflate, gzip\r\n\r\n")
ANNOUNCE_SCREEN = ["announce 요청 (event=started)",
                   "info_hash: 0123456789abcdef0123456789abcdef01234567",
                   "peer_id: -TR4060-k8hj0wgej6ch (Transmission)",
                   "port: 51413",
                   "uploaded: 0, downloaded: 0, left: 6114656256",
                   "compact: 1, numwant: 80",
                   "Host: tracker.test.local:6969",
                   "User-Agent: Transmission/4.0.6"]
PEERS = [("192.0.2.10", 51413), ("198.51.100.20", 6881), ("203.0.113.30", 6889)]
REPLY_BODY = benc({b"complete": 1234, b"incomplete": 56, b"interval": 1800, b"min interval": 900,
                   b"peers": compact(PEERS)})
REPLY_SCREEN = ["announce 응답 200 OK, peers 3개",
                "interval: 1800초 (min interval: 900초)",
                "complete: 1234 (시드), incomplete: 56 (받는 중)",
                "peers 3개 (compact)",
                "  192.0.2.10:51413", "  198.51.100.20:6881", "  203.0.113.30:6889"]


def http_reply(body: bytes, headers: bytes = b"") -> bytes:
    return (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" + headers
            + b"Content-Length: %d\r\n\r\n" % len(body) + body)


# ---- DHT: BEP 5 문서의 예
PING_Q = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"
PING_R = b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re"
FIND_NODE_Q = b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe"
GET_PEERS_Q = b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe"
GET_PEERS_R = b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re"
ANNOUNCE_PEER_Q = (b"d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz123456"
                   b"4:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe")
DHT_ERROR = b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee"
ID_A = "id: 6162636465666768696a30313233343536373839"      # "abcdefghij0123456789"
ID_M = "6d6e6f707172737475767778797a313233343536"          # "mnopqrstuvwxyz123456"


class BtTest(unittest.TestCase):
    def setUp(self):
        app_bt.reset_state()
        app_select.reset_state()

    tearDown = setUp


class TestBencode(unittest.TestCase):
    def test_bep3_examples(self):
        for raw, value in ((b"4:spam", b"spam"), (b"0:", b""), (b"i3e", 3), (b"i-3e", -3), (b"i0e", 0),
                           (b"l4:spam4:eggse", [b"spam", b"eggs"]), (b"le", []), (b"de", {}),
                           (b"d3:cow3:moo4:spam4:eggse", {b"cow": b"moo", b"spam": b"eggs"}),
                           (b"d4:spaml1:a1:bee", {b"spam": [b"a", b"b"]}),
                           (b"5:a:e\x00\xff", b"a:e\x00\xff"),                   # 문자열 안은 아무 바이트나
                           (b"03:abc", b"abc"),                  # 문자열 길이 앞 0은 BEP 3이 막지 않음 (정수만)
                           (b"i12345678901234567890e", 12345678901234567890)):
            self.assertEqual(bdecode(raw), value, raw)

    def test_broken_is_value_error(self):
        broken = [b"", b"i03e", b"i-0e", b"ie", b"i-e", b"i12", b"i1.5e", b"i+1e", b"5:abc", b"-1:a", b"3abc",
                  b"l", b"li1e", b"d", b"d3:fooe", b"di1ei2ee", b"x", b"e", b"i1ei2e", b"4:spamX",
                  b"i" + b"9" * 100 + b"e", b"l" * 33 + b"e" * 33]
        for raw in broken:
            with self.assertRaises(ValueError, msg=raw):
                bdecode(raw)

    def test_depth_limit(self):
        nested: list = []
        for _ in range(31):
            nested = [nested]
        self.assertEqual(bdecode(b"l" * 32 + b"e" * 32), nested)          # 32겹까지는 된다
        with self.assertRaises(ValueError):
            bdecode(b"d1:a" * 40 + b"i1e" + b"e" * 40)


class TestTrackerRequest(BtTest):
    def test_transmission_announce(self):
        app = parse_bt_tracker(ANNOUNCE)
        self.assertEqual(app.name, "BT-TRACKER")
        self.assertEqual(screen(app), ANNOUNCE_SCREEN)
        f = app.fields
        self.assertEqual((f["is_request"], f["kind"], f["path"], f["info_hash"], f["peer_id"], f["client"],
                          f["event"]),
                         (True, "announce", "/announce", INFO_HASH.hex(), "-TR4060-k8hj0wgej6ch", "Transmission",
                          "started"))
        self.assertEqual((f["params"]["port"], f["params"]["left"], f["params"]["key"]),
                         ("51413", "6114656256", "6e2b1a3f"))
        self.assertEqual(f["headers"], {"host": "tracker.test.local:6969", "user-agent": "Transmission/4.0.6"})

    def test_info_hash_any_bytes(self):
        # info_hash·peer_id는 아무 바이트나 될 수 있다 → 퍼센트 디코딩한 bytes를 그대로 hex로
        for h in (bytes(range(20)), b"AZaz09-._~+%&=?#/ \xff!", bytes(range(236, 256))):
            q = b"GET /announce?info_hash=" + quote_from_bytes(h, safe="").encode() + b"&port=1 HTTP/1.1\r\n\r\n"
            self.assertEqual(parse_bt_tracker(q).fields["info_hash"], h.hex(), h)
        raw_plus = parse_bt_tracker(b"GET /a?info_hash=%2b+%2B HTTP/1.0\r\n\r\n")    # '+'는 공백이 아님
        self.assertEqual(raw_plus.fields["info_hash"], "2b2b2b")
        self.assertIn("info_hash: 2b2b2b (3 bytes)", raw_plus.lines)

    def test_event_and_minimal(self):
        stopped = parse_bt_tracker(ANNOUNCE.replace(b"event=started", b"event=stopped"))
        self.assertEqual(stopped.summary, "announce 요청 (event=stopped)")
        bare = parse_bt_tracker(b"GET /announce?info_hash=%01%02 HTTP/1.1\r\n\r\n")
        self.assertEqual(screen(bare), ["announce 요청", "info_hash: 0102 (2 bytes)"])
        self.assertIsNone(bare.fields["event"])

    def test_scrape_and_absolute_uri(self):
        hashes = [bytes([i]) * 20 for i in range(12)]
        q = b"GET /scrape?" + b"&".join(b"info_hash=" + quote_from_bytes(h, safe="").encode() for h in hashes)
        app = parse_bt_tracker(q + b" HTTP/1.1\r\nHost: t\r\n\r\n")
        self.assertEqual(app.summary, "scrape 요청 (info_hash 12개)")
        self.assertEqual(app.lines[:MAX_PEERS], [f"info_hash: {h.hex()}" for h in hashes[:MAX_PEERS]])
        self.assertEqual(app.lines[MAX_PEERS:], ["… info_hash 2개 더", "Host: t"])
        self.assertEqual(app.fields["kind"], "scrape")
        self.assertEqual(app.fields["info_hashes"], [h.hex() for h in hashes])
        # 프록시를 거치는 요청: GET http://트래커:포트/announce?…
        proxy = parse_bt_tracker(ANNOUNCE.replace(b"GET /announce", b"GET http://tracker.test.local:6969/announce"))
        self.assertEqual(screen(proxy), ANNOUNCE_SCREEN)
        self.assertEqual(proxy.fields["path"], "/announce")

    def test_not_tracker_is_none(self):
        # None이면 parse_app이 parse_http로 넘긴다
        for data in (b"GET / HTTP/1.1\r\nHost: neverssl.com\r\n\r\n", b"GET /search?q=announce HTTP/1.1\r\n\r\n",
                     b"GET /announce HTTP/1.1\r\n\r\n", b"POST /announce?info_hash=%01 HTTP/1.1\r\n\r\n",
                     b"GET /announce?info_hash=%01 FTP/1.0\r\n\r\n", b"\x13BitTorrent protocol", b"",
                     b"<html>continuation</html>"):
            self.assertIsNone(parse_bt_tracker(data), data)

    def test_untrusted_text_is_escaped(self):
        q = (b"GET /announce?info_hash=%01&peer_id=%1B%5B31m%00%9Babcdefghijklmno&event=%1B]0;x%07 HTTP/1.1\r\n"
             b"User-Agent: evil\x1b[2J\xc2\x9b\r\n\r\n")
        lines = screen(parse_bt_tracker(q))
        self.assertEqual(lines[0], "announce 요청 (event=\\x1b]0;x\\x07)")
        self.assertIn("peer_id: \\x1b[31m\\x00\\x9babcdefghijklmno", lines)
        self.assertIn("User-Agent: evil\\x1b[2J\\x9b", lines)              # C1(U+009B)도
        self.assertFalse(any("\x1b" in line or "\x9b" in line for line in lines))


class TestTrackerResponse(BtTest):
    def test_compact_peers(self):
        app = parse_bt_tracker(http_reply(REPLY_BODY))
        self.assertEqual(screen(app), REPLY_SCREEN)
        f = app.fields
        self.assertEqual((f["is_request"], f["kind"], f["status_code"], f["interval"], f["min_interval"],
                          f["complete"], f["incomplete"], f["peer_count"], f["body_complete"]),
                         (False, "announce", 200, 1800, 900, 1234, 56, 3, True))
        self.assertEqual(f["peers"], ["192.0.2.10:51413", "198.51.100.20:6881", "203.0.113.30:6889"])

    def test_many_peers(self):
        peers = [(f"10.0.{i // 256}.{i % 256}", 6881) for i in range(50)]
        app = parse_bt_tracker(http_reply(benc({b"interval": 1800, b"peers": compact(peers)})))
        self.assertEqual(app.summary, "announce 응답 200 OK, peers 50개")
        self.assertEqual(app.lines[1:], ["peers 50개 (compact)"] + [f"  10.0.0.{i}:6881" for i in range(MAX_PEERS)]
                         + ["  … 40개 더"])
        self.assertEqual((app.fields["peer_count"], len(app.fields["peers"])), (50, 50))

    def test_dict_peers_and_peers6(self):
        listed = benc({b"interval": 900, b"peers": [
            {b"ip": b"192.0.2.10", b"peer id": b"-TR4060-aaaaaaaaaaaa", b"port": 51413},
            {b"ip": b"2001:db8::7", b"port": 6881}, {b"ip": b"no-port"}]})
        self.assertEqual(screen(parse_bt_tracker(http_reply(listed))),
                         ["announce 응답 200 OK, peers 2개", "interval: 900초", "peers 2개 (사전 목록)",
                          "  192.0.2.10:51413", "  [2001:db8::7]:6881"])
        v6 = ipaddress.IPv6Address("2001:db8::1").packed + struct.pack("!H", 6881)
        app = parse_bt_tracker(http_reply(benc({b"interval": 900, b"peers": b"", b"peers6": v6})))
        self.assertEqual(screen(app), ["announce 응답 200 OK, peers 1개", "interval: 900초", "peers 0개 (compact)",
                                       "peers6 1개 (compact)", "  [2001:db8::1]:6881"])
        self.assertEqual(app.fields["peers"], ["[2001:db8::1]:6881"])

    def test_failure_and_warning(self):
        failed = parse_bt_tracker(http_reply(benc({b"failure reason": b"torrent not registered"})))
        self.assertEqual(screen(failed), ["announce 응답 200 OK: 실패 - torrent not registered"])
        self.assertEqual(failed.fields["failure_reason"], "torrent not registered")
        warned = parse_bt_tracker(http_reply(benc({b"interval": 1800, b"peers": b"",
                                                   b"warning message": b"slow \x1b[1mdown"})))
        self.assertEqual(warned.lines, ["interval: 1800초", "warning message: slow \\x1b[1mdown", "peers 0개 (compact)"])

    def test_compressed_and_chunked_bodies(self):
        raw = zlib.compressobj(wbits=-15)
        raw_deflate = raw.compress(REPLY_BODY) + raw.flush()
        half = len(REPLY_BODY) // 2
        chunked = b"%x\r\n%s\r\n%x\r\n%s\r\n0\r\n\r\n" % (half, REPLY_BODY[:half], len(REPLY_BODY) - half,
                                                          REPLY_BODY[half:])
        gz = gzip.compress(REPLY_BODY)
        replies = [
            http_reply(gz, b"Content-Encoding: gzip\r\n"),
            http_reply(zlib.compress(REPLY_BODY), b"Content-Encoding: deflate\r\n"),
            http_reply(raw_deflate, b"Content-Encoding: deflate\r\n"),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n"
            + b"%x\r\n%s\r\n0\r\n\r\n" % (len(gz), gz),
        ]
        for reply in replies:
            self.assertEqual(screen(parse_bt_tracker(reply)), REPLY_SCREEN, reply[:80])

    def test_truncated_body(self):
        # 본문이 다음 세그먼트로 이어지면 읽은 데까지만 (peers 앞에서 잘림)
        head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(REPLY_BODY)
        app = parse_bt_tracker(head + REPLY_BODY[:-10])
        self.assertEqual(screen(app), ["announce 응답 200 OK", "interval: 1800초 (min interval: 900초)",
                                       "complete: 1234 (시드), incomplete: 56 (받는 중)",
                                       "(bencode 본문이 다음 세그먼트로 이어짐: 읽은 데까지만 표시)"])
        self.assertFalse(app.fields["body_complete"])
        gz = gzip.compress(REPLY_BODY)
        cut = parse_bt_tracker(http_reply(gz, b"Content-Encoding: gzip\r\n")[:-30])  # gzip도 앞부분만 풀림
        self.assertEqual(cut.summary, "announce 응답 200 OK")

    def test_scrape_reply(self):
        body = benc({b"files": {INFO_HASH: {b"complete": 5, b"downloaded": 50, b"incomplete": 10, b"name": b"x"}},
                     b"flags": {b"min_request_interval": 900}})
        app = parse_bt_tracker(http_reply(body))
        self.assertEqual(screen(app), ["scrape 응답 200 OK, 파일 1개",
                                       f"{INFO_HASH.hex()}: complete=5, downloaded=50, incomplete=10"])
        self.assertEqual(app.fields["files"], {INFO_HASH.hex(): {"complete": 5, "downloaded": 50, "incomplete": 10}})

    def test_not_tracker_reply_is_none(self):
        for reply in (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>",
                      b"HTTP/1.1 200 OK\r\n\r\n{\"interval\": 1}", b"HTTP/1.1 200 OK\r\n\r\nd3:foo3:bare",
                      b"HTTP/1.1 200 OK\r\n\r\ndoctype", b"HTTP/1.1 304 Not Modified\r\n\r\n",
                      b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n",                # 헤더가 아직 안 끝남
                      b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\nnot gzip at all"):
            self.assertIsNone(parse_bt_tracker(reply), reply)


class TestPeer(BtTest):
    def test_handshake_bitfield_extended(self):
        app = parse_bt_peer(A2B, HANDSHAKE + msg(5, b"\xff\xff\xf0") + EXT_HANDSHAKE)
        self.assertEqual(app.name, "BT-PEER")
        self.assertEqual(screen(app), HANDSHAKE_SCREEN + ["bitfield 3 bytes, 가진 조각 20개"] + EXT_SCREEN)
        f = app.fields
        self.assertEqual(f["handshake"], {"info_hash": INFO_HASH.hex(), "peer_id": "-TR4060-k8hj0wgej6ch",
                                          "client": "Transmission", "reserved": "0000000000100005",
                                          "extensions": ["Extension Protocol", "Fast", "DHT"]})
        self.assertEqual([m["name"] for m in f["messages"]], ["handshake", "bitfield", "extended"])
        self.assertEqual(f["messages"][1]["pieces"], 20)
        self.assertEqual(f["messages"][2]["m"], {"ut_metadata": 3, "ut_pex": 1})      # 0(끈 확장)은 뺌
        self.assertEqual((f["continued"], f["lost"]), (0, False))

    def test_every_small_message(self):
        app = parse_bt_peer(A2B, SMALL)
        self.assertEqual(screen(app), SMALL_SCREEN)
        request = app.fields["messages"][6]
        self.assertEqual((request["index"], request["begin"], request["block"], request["length"]),
                         (7, 16384, 16384, 13))
        self.assertEqual(app.fields["messages"][8]["port"], 51413)

    def test_extended_names_come_from_receiver(self):
        # 확장 메시지 ID는 받는 쪽이 자기 확장 handshake(m)로 정한다 (BEP 10)
        parse_bt_peer(A2B, HANDSHAKE + EXT_HANDSHAKE)                     # A: ut_pex=1, ut_metadata=3
        back = parse_bt_peer(B2A, HANDSHAKE_B + msg(20, b"\x03" + benc({b"msg_type": 0, b"piece": 0})))
        self.assertEqual(back.lines[-1], "extended ut_metadata 25 bytes")  # B → A: A의 m으로 이름
        self.assertEqual(back.fields["messages"][-1]["ext_name"], "ut_metadata")
        unknown = parse_bt_peer(A2B, msg(20, b"\x02" + bytes(10)))         # A → B: B는 m을 안 보냈음
        self.assertEqual(unknown.summary, "extended id=2 10 bytes")
        parse_bt_peer(B2A, msg(20, b"\x00" + benc({b"m": {b"ut_metadata": 2}})))
        self.assertEqual(parse_bt_peer(A2B, msg(20, b"\x02" + bytes(10))).summary, "extended ut_metadata 10 bytes")

    def test_piece_across_segments(self):
        segments = [msg(1) + PIECE[:1443], PIECE[1443:2891], PIECE[2891:] + msg(4, struct.pack("!I", 3))]
        apps = [parse_bt_peer(B2A, s) for s in segments]
        self.assertEqual([screen(a) for a in apps], [
            ["unchoke", "piece index=3 begin=16384 block=16384 bytes", "  (다음 세그먼트로 이어짐: 1430/16384 bytes)"],
            ["piece index=3 begin=16384 이어짐 1448 bytes (2878/16384)"],
            ["piece index=3 begin=16384 이어짐 13506 bytes (16384/16384 끝)", "have index=3"]])
        self.assertEqual([a.fields["continued"] for a in apps], [0, 1448, 13506])
        self.assertEqual(apps[0].fields["messages"][1]["block"], 16384)
        self.assertEqual([m["name"] for m in apps[2].fields["messages"]], ["have"])

    def test_split_anywhere(self):
        # 같은 바이트를 어디서 둘로 잘라도 메시지 종류·순서가 같고, 경계를 잃지 않는다
        piece = msg(7, struct.pack("!II", 3, 0) + bytes(range(256)) * 4)
        stream = (HANDSHAKE + msg(5, b"\xff\xf0") + EXT_HANDSHAKE + msg(1) + piece + msg(4, struct.pack("!I", 3))
                  + b"\x00\x00\x00\x00" + msg(6, struct.pack("!III", 3, 1024, 1024)))
        names = ["handshake", "bitfield", "extended", "unchoke", "piece", "have", "keep-alive", "request"]
        for cut in range(1, len(stream)):
            app_bt.reset_state()
            first, second = parse_bt_peer(B2A, stream[:cut]), parse_bt_peer(B2A, stream[cut:])
            got = [m["name"] for m in first.fields["messages"] + second.fields["messages"]]
            self.assertEqual(got, names, cut)
            self.assertFalse(first.fields["lost"] or second.fields["lost"], cut)
            st = app_bt._flows[B2A]
            self.assertEqual((st.left, st.buf), (0, b""), cut)
            if cut < 68:
                self.assertEqual(first.summary, f"(handshake가 다음 세그먼트로 이어짐: {cut}/68 bytes)")
                self.assertEqual(second.summary, "handshake")

    def test_bitfield_across_segments(self):
        bitfield = msg(5, b"\xff" * 2999 + b"\xf0")                      # 조각 23996개
        apps = [parse_bt_peer(A2B, s) for s in (bitfield[:1448], bitfield[1448:2896], bitfield[2896:])]
        self.assertEqual([screen(a) for a in apps], [
            ["bitfield 3000 bytes", "  (다음 세그먼트로 이어짐: 1443/3000 bytes)"],
            ["bitfield 이어짐 1448 bytes (2891/3000)"],
            ["bitfield 이어짐 109 bytes (3000/3000 끝), 가진 조각 23996개"]])

    def test_lost_boundary_and_resync(self):
        # 캡처 손실·재전송으로 경계를 잃으면 표시하고, 자주 나오는 머리(16 KiB piece)에서 다시 맞춘다
        app = parse_bt_peer(B2A, b"\x55" * 100 + PIECE[:500])
        self.assertEqual(screen(app), ["(메시지 경계를 잃음: 100 bytes 건너뛰고 다시 맞춤)",
                                       "piece index=3 begin=16384 block=16384 bytes",
                                       "  (다음 세그먼트로 이어짐: 487/16384 bytes)"])
        self.assertTrue(app.fields["lost"])
        app_bt.reset_state()
        # 못 찾으면 그 방향은 계속 잃은 상태. 머리가 세그먼트 경계에 걸쳐도 찾는다
        lost = parse_bt_peer(B2A, b"\x55" * 1446 + PIECE[:2])
        self.assertEqual(screen(lost), ["(메시지 경계를 잃음: 1448 bytes)"])
        again = parse_bt_peer(B2A, PIECE[2:200])
        self.assertEqual(screen(again), ["(메시지 경계를 다시 맞춤)", "piece index=3 begin=16384 block=16384 bytes",
                                         "  (다음 세그먼트로 이어짐: 187/16384 bytes)"])
        # 새 handshake(같은 주소·포트로 새 연결)에서도 다시 맞춘다
        parse_bt_peer(A2B, b"\x77" * 300)
        self.assertEqual(screen(parse_bt_peer(A2B, HANDSHAKE)), ["(메시지 경계를 다시 맞춤)"] + HANDSHAKE_SCREEN)

    def test_missing_segment_inside_piece(self):
        # piece 도중 세그먼트 하나가 캡처되지 않음 → piece가 끝나기 전에 다음 piece 머리가 보이면 거기서 바로 다시 해석
        two = PIECE + msg(7, struct.pack("!II", 3, 32768) + BLOCK)
        segments = [two[i:i + 1448] for i in range(0, len(two), 1448)]
        del segments[3]
        apps = [parse_bt_peer(B2A, s) for s in segments]
        self.assertEqual(screen(apps[10]), [
            "piece index=3 begin=16384 이어짐 469 bytes (14936/16384에서 끊김: 캡처 손실·재전송)",
            "piece index=3 begin=32768 block=16384 bytes", "  (다음 세그먼트로 이어짐: 966/16384 bytes)"])
        self.assertEqual([a.fields["gap"] for a in apps].count(True), 1)
        self.assertFalse(any(a.fields["lost"] for a in apps))
        self.assertEqual(apps[-1].summary, "piece index=3 begin=32768 이어짐 938 bytes (16384/16384 끝)")

    def test_bad_lengths_lose_boundary(self):
        # 길이가 정해진 메시지인데 길이가 다르거나, 모르는 ID, 너무 긴 메시지, 연달은 0 → 경계를 잃음
        for data in (struct.pack("!IB", 2, 1) + b"\x00", struct.pack("!IB", 6, 4) + bytes(5),
                     struct.pack("!IB", 5, 99) + bytes(4), struct.pack("!IB", 3 << 20, 5),
                     struct.pack("!IB", 8, 7) + bytes(7), bytes(64)):
            app_bt.reset_state()
            self.assertEqual(parse_bt_peer(A2B, data).summary, f"(메시지 경계를 잃음: {len(data)} bytes)", data)

    def test_new_flow_without_handshake(self):
        # handshake를 못 본 방향(캡처 손실)이라도 메시지 경계에서 시작하면 그대로 읽는다
        self.assertEqual(screen(parse_bt_peer(B2A, msg(4, struct.pack("!I", 5)))), ["have index=5"])

    def test_directions_are_separate(self):
        parse_bt_peer(A2B, HANDSHAKE)
        parse_bt_peer(B2A, HANDSHAKE_B)
        start = parse_bt_peer(B2A, msg(1) + PIECE[:1000])
        request = parse_bt_peer(A2B, msg(6, struct.pack("!III", 3, 32768, 16384)))
        end = parse_bt_peer(B2A, PIECE[1000:] + msg(4, struct.pack("!I", 3)))
        self.assertEqual(start.lines[-1], "  (다음 세그먼트로 이어짐: 987/16384 bytes)")
        self.assertEqual(screen(request), ["request index=3 begin=32768 length=16384"])
        self.assertEqual(screen(end), ["piece index=3 begin=16384 이어짐 15397 bytes (16384/16384 끝)", "have index=3"])

    def test_header_cut_at_segment_end(self):
        self.assertEqual(screen(parse_bt_peer(A2B, msg(1)[:3])), ["(메시지 머리가 다음 세그먼트로 이어짐: 3/4 bytes)"])
        self.assertEqual(screen(parse_bt_peer(A2B, msg(1)[3:] + PIECE[:9])),
                         ["unchoke", "(메시지 머리가 다음 세그먼트로 이어짐: 9/13 bytes)"])
        self.assertEqual(parse_bt_peer(A2B, PIECE[9:20]).lines, ["  (다음 세그먼트로 이어짐: 7/16384 bytes)"])

    def test_large_and_broken_extended(self):
        big = msg(20, b"\x00" + benc({b"v": b"x" * MAX_EXTENDED}))          # 크면 모으지 않고 크기만
        self.assertEqual(screen(parse_bt_peer(A2B, big)), [f"extended handshake {len(big) - 6} bytes"])
        broken = parse_bt_peer(A2B, msg(20, b"\x00" + b"d1:v"))
        self.assertEqual(broken.summary, "extended handshake 4 bytes (bencode 사전이 아님)")
        self.assertEqual(screen(parse_bt_peer(A2B, msg(21, bytes(48)) + msg(22, bytes(80)))),
                         ["hash request 48 bytes", "hashes 80 bytes"])

    def test_untrusted_text_is_escaped(self):
        peer_id = b"-TR4060-\x1b[31mred\x9b\x00xx"
        ext = msg(20, b"\x00" + benc({b"m": {b"ut_\x1bpex": 1}, b"v": "evil\x1b]0;t\x07\u009b".encode()}))
        lines = screen(parse_bt_peer(A2B, HANDSHAKE[:48] + peer_id + ext))
        self.assertIn("  peer_id: -TR4060-\\x1b[31mred\\x9b\\x00xx (Transmission)", lines)
        self.assertIn("  v: evil\\x1b]0;t\\x07\\x9b", lines)
        self.assertIn("  m: ut_\\x1bpex=1", lines)
        self.assertFalse(any("\x1b" in line or "\x9b" in line or "\x00" in line for line in lines))

    def test_item_limit(self):
        app = parse_bt_peer(A2B, b"".join(msg(4, struct.pack("!I", i)) for i in range(30)))
        self.assertEqual(app.summary, "have index=0")
        self.assertEqual(len(app.lines), MAX_ITEMS)
        self.assertEqual(app.lines[-1], "… 10줄 더 (모두 30줄)")
        self.assertEqual(len(app.fields["messages"]), 30)

    def test_flow_limit(self):
        for i in range(MAX_FLOWS + 1):
            parse_bt_peer(("192.0.2.1", 40000 + i, "198.51.100.2", 6881), HANDSHAKE)
        self.assertEqual(len(app_bt._flows), MAX_FLOWS)
        self.assertNotIn(("192.0.2.1", 40000, "198.51.100.2", 6881), app_bt._flows)   # 가장 오래 안 쓴 방향

    def test_empty_is_value_error(self):
        with self.assertRaises(ValueError):
            parse_bt_peer(A2B, b"")


class TestDht(BtTest):
    def test_bep5_examples(self):
        expected = [
            (PING_Q, ["query ping t=6161", ID_A]),
            (PING_R, ["response t=6161", f"id: {ID_M}"]),
            (FIND_NODE_Q, ["query find_node t=6161", ID_A, f"target: {ID_M}"]),
            (GET_PEERS_Q, ["query get_peers t=6161", ID_A, f"info_hash: {ID_M}"]),
            (GET_PEERS_R, ["response t=6161", ID_A, "token: 8 bytes",
                           "values 2개: 97.120.106.101:11893, 105.100.104.116:28269"]),
            (ANNOUNCE_PEER_Q, ["query announce_peer t=6161", ID_A, f"info_hash: {ID_M}",
                               "port: 6881 (implied_port=1: 보낸 UDP 포트를 쓰라는 뜻)", "token: 8 bytes"]),
            (DHT_ERROR, ["error 201 A Generic Error Ocurred t=6161"]),
        ]
        for raw, lines in expected:
            app = parse_bt_dht(raw)
            self.assertEqual(app.name, "BT-DHT")
            self.assertEqual(screen(app), lines, raw)
        f = parse_bt_dht(GET_PEERS_R).fields
        self.assertEqual((f["t"], f["y"], f["q"], f["id"], f["token_len"]),
                         ("6161", "r", None, "6162636465666768696a30313233343536373839", 8))
        self.assertEqual(f["values"], ["97.120.106.101:11893", "105.100.104.116:28269"])
        self.assertEqual(parse_bt_dht(GET_PEERS_Q).fields["items"], {"id": ID_A[4:], "info_hash": ID_M})
        self.assertEqual(parse_bt_dht(DHT_ERROR).fields["error"], [201, "A Generic Error Ocurred"])

    def test_nodes_ip_and_version(self):
        nodes = b"".join(bytes([i]) * 20 + socket.inet_aton(f"192.0.2.{i}") + struct.pack("!H", 6880 + i)
                         for i in range(1, 9))
        raw = benc({b"ip": socket.inet_aton("203.0.113.9") + struct.pack("!H", 51413),   # BEP 42 → "d2:ip…"
                    b"r": {b"id": b"mnopqrstuvwxyz123456", b"nodes": nodes, b"token": b"tk"},
                    b"t": b"\x00\x07", b"v": b"UT\x01\x02", b"y": b"r"})
        self.assertTrue(raw.startswith(b"d2:ip6:"))
        app = parse_bt_dht(raw)
        self.assertEqual(screen(app), [
            "response t=0007", f"id: {ID_M}", "token: 2 bytes",
            "nodes 8개: 192.0.2.1:6881, 192.0.2.2:6882, 192.0.2.3:6883, 192.0.2.4:6884, …",
            "ip: 203.0.113.9:51413 (응답한 노드가 본 질의한 쪽 주소)", "v: UT 0102"])
        self.assertEqual(len(app.fields["nodes"]), 8)
        self.assertEqual(app.fields["ip"], "203.0.113.9:51413")

    def test_other_queries_and_keys(self):
        raw = benc({b"a": {b"id": b"abcdefghij0123456789", b"target": b"mnopqrstuvwxyz123456", b"seq": 3},
                    b"q": b"sample_infohashes", b"t": b"aa", b"v": b"\x01\x1b", b"y": b"q"})
        self.assertEqual(screen(parse_bt_dht(raw)), ["query sample_infohashes t=6161", ID_A, f"target: {ID_M}",
                                                     "그 밖의 키: seq", "v: \\x01\\x1b"])
        self.assertEqual(parse_bt_dht(b"d1:eli201ee1:t2:aa1:y1:ee").summary, "error 201 t=6161")

    def test_not_krpc_is_none(self):
        for raw in (b"d3:foo3:bare", b"d1:t2:aa1:y1:xe", b"d1:y1:qe", b"d1:t2:aa1:yi1ee", b"li1ee", b"i1e",
                    b"4:spam"):
            self.assertIsNone(parse_bt_dht(raw), raw)

    def test_broken_is_value_error(self):
        for raw in (b"", b"d1:ad2:id20:abc", b"d1:ad2:id20:abcdefghij0123456789e1:q4:pinge-", b"dx"):
            with self.assertRaises(ValueError, msg=raw):
                parse_bt_dht(raw)


class TestThroughParseApp(BtTest):
    """parse_app → (실제) BitTorrent 파서. 피어는 아무 포트나, 트래커는 HTTP보다 먼저, DHT는 UDP 내용으로."""

    A, B = ("192.0.2.1", 51413), ("198.51.100.2", 6881)

    def app(self, proto, src, dst, payload, ports=DEFAULT_PORTS):
        key = canonical_key(src[0], src[1], dst[0], dst[1])
        return parse_app(key, proto, src[1], dst[1], payload, ports)

    def test_peer_both_directions(self):
        first = self.app("TCP", self.A, self.B, HANDSHAKE + msg(5, b"\xff\xf0"))
        back = self.app("TCP", self.B, self.A, HANDSHAKE_B + msg(14))
        then = self.app("TCP", self.A, self.B, msg(2))           # handshake 뒤 세그먼트도 피어 (연결을 기억)
        self.assertEqual([a.name for a in (first, back, then)], ["BT-PEER"] * 3)
        self.assertEqual(screen(back)[-1], "have all")
        self.assertEqual(screen(then), ["interested"])
        self.assertEqual(set(app_bt._flows), {A2B, B2A})        # 방향마다 따로 기억

    def test_peer_on_any_port(self):
        for port in (80, 443, 25, 110, 143, 53, 6969):
            app = self.app("TCP", ("192.0.2.5", 50000 + port), ("198.51.100.9", port), HANDSHAKE)
            self.assertEqual((app.name, app.summary), ("BT-PEER", "handshake"), port)

    def test_tracker_before_http(self):
        tracker, client = ("198.51.100.50", 6969), ("192.0.2.1", 50001)
        self.assertEqual(self.app("TCP", client, tracker, ANNOUNCE).summary, "announce 요청 (event=started)")
        self.assertEqual(screen(self.app("TCP", tracker, client, http_reply(REPLY_BODY))), REPLY_SCREEN)
        cont = self.app("TCP", tracker, client, b"more bencode bytes")
        self.assertEqual((cont.name, cont.summary), ("HTTP", "continuation 18 bytes"))
        web, browser = ("198.51.100.60", 80), ("192.0.2.1", 50002)
        self.assertEqual(self.app("TCP", browser, web, ANNOUNCE).name, "BT-TRACKER")    # 80번 트래커도 내용으로
        self.assertEqual(self.app("TCP", web, browser, http_reply(REPLY_BODY)).name, "BT-TRACKER")
        self.assertEqual(self.app("TCP", browser, web, b"GET / HTTP/1.1\r\nHost: neverssl.com\r\n\r\n").name, "HTTP")
        self.assertEqual(self.app("TCP", web, browser, http_reply(b"<html></html>")).name, "HTTP")
        other = self.app("TCP", ("192.0.2.1", 50003), ("198.51.100.70", 2710), ANNOUNCE)   # 포트가 표에 없어도
        self.assertEqual(other.name, "BT-TRACKER")

    def test_port_override(self):
        from tests.test_app_select import cli_ports
        ports = cli_ports("bittorrent=2710")
        self.assertEqual(ports["bittorrent"], (2710,))
        tracker, client = ("198.51.100.70", 2710), ("192.0.2.1", 50004)
        self.assertEqual(self.app("TCP", tracker, client, b"rest of body", ports).summary, "continuation 12 bytes")
        self.assertIsNone(self.app("TCP", tracker, client, b"rest of body"))          # 기본 표에서는 [DATA]

    def test_dht_over_udp(self):
        query = self.app("UDP", self.A, self.B, GET_PEERS_Q)
        reply = self.app("UDP", self.B, self.A, GET_PEERS_R)
        self.assertEqual((query.name, query.summary), ("BT-DHT", "query get_peers t=6161"))
        self.assertEqual(reply.lines[-1], "values 2개: 97.120.106.101:11893, 105.100.104.116:28269")
        self.assertIsNone(self.app("UDP", self.A, self.B, b"\x41\x00\x12\x34" + bytes(16)))   # uTP 등
        self.assertIsNone(self.app("UDP", self.A, self.B, b"d1:t2:aa1:y1:xe"))               # KRPC 아님
        with self.assertRaises(ValueError):                                                   # 깨짐 → [DATA]
            self.app("UDP", self.A, self.B, b"d1:ad2:id")


class TestThroughDecode(BtTest):
    """프레임 → decode() → parse_app → BitTorrent 파서 → format_packet 화면 줄."""

    def run_frames(self, frames, ports=DEFAULT_PORTS):
        from src import output              # A의 파일 — 깨져도 위쪽 테스트는 돌게 여기서 불러옴
        from src.decode import decode
        result = []
        for no, frame in enumerate(frames, 1):
            with contextlib.redirect_stderr(io.StringIO()):
                pkt = decode(Captured(no=no, ts=1.0, direction="IN", frame=frame), ports)
            result.append((pkt, output.format_packet(pkt)))
        return result

    def tcp(self, sport, dport, data, src="192.0.2.1", dst="198.51.100.2"):
        return eth(ipv4(tcp_header(sport, dport, 0x18) + data, src=src, dst=dst))

    def udp(self, sport, dport, data, src="192.0.2.1", dst="198.51.100.2"):
        return eth(ipv4(struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data, proto=17, src=src, dst=dst))

    def test_peer_lines(self):
        (pkt, lines), (back, back_lines) = self.run_frames([
            self.tcp(51413, 6881, HANDSHAKE + msg(5, b"\xff\xf0")),
            self.tcp(6881, 51413, HANDSHAKE_B + msg(1) + PIECE[:1400], src="198.51.100.2", dst="192.0.2.1")])
        start = lines.index("  [BT-PEER] handshake")
        self.assertEqual(lines[start + 1:], [
            "           info_hash: 0123456789abcdef0123456789abcdef01234567",
            "           peer_id: -TR4060-k8hj0wgej6ch (Transmission)",
            "           reserved: 0000000000100005 (Extension Protocol, Fast, DHT)",
            "         bitfield 2 bytes, 가진 조각 12개"])
        self.assertEqual(back_lines[-3:], ["         unchoke", "         piece index=3 begin=16384 block=16384 bytes",
                                           "           (다음 세그먼트로 이어짐: 1387/16384 bytes)"])
        self.assertEqual(pkt.app.name, back.app.name)

    def test_tracker_and_dht_lines(self):
        result = self.run_frames([
            self.tcp(50001, 6969, ANNOUNCE),
            self.tcp(6969, 50001, http_reply(REPLY_BODY), src="198.51.100.2", dst="192.0.2.1"),
            self.udp(51413, 6881, GET_PEERS_Q)])
        self.assertIn("  [BT-TRACKER] announce 요청 (event=started)", result[0][1])
        self.assertIn("         info_hash: 0123456789abcdef0123456789abcdef01234567", result[0][1])
        self.assertEqual(result[1][1][-4:], ["         peers 3개 (compact)", "           192.0.2.10:51413",
                                             "           198.51.100.20:6881", "           203.0.113.30:6889"])
        self.assertIn("  [BT-DHT] query get_peers t=6161", result[2][1])


if __name__ == "__main__":
    unittest.main()
