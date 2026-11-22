# =============================================================================
# TLS 레코드 헤더(parse_tls) 단위 테스트 (#13)
# - curl ↔ 서버의 TLS handshake에 나오는 레코드 모양 그대로 확인
#   (레코드 헤더·Handshake 헤더는 실제 값, 내용은 해석하지 않으므로 0이나 암호문 흉내 바이트)
# =============================================================================
import contextlib
import io
import struct
import unittest

from src.decode.app_select import parse_app
from src.decode.app_tls import MAX_RECORD_LINES, parse_tls
from src.models import DEFAULT_PORTS, Captured
from tests.test_link_ip import eth, ipv4, tcp_header

# 암호문 흉내: 0x80~0xff 반복 → 어디서 잘라도 Content Type(20~24)으로 시작하지 않는다
CIPHER = bytes(range(0x80, 0x100)) * 32

# curl → 서버 ClientHello: 레코드 Version은 호환성 때문에 TLS 1.0, Length 512
# (Handshake 헤더 01 0001fc = Client Hello 508바이트, 그 안 version 0303, 나머지는 0)
CLIENT_HELLO = bytes.fromhex("16 0301 0200  01 0001fc 0303") + bytes(506)
# 서버 → curl ServerHello: TLS 1.3 연결도 레코드 Version은 TLS 1.2, Length 122
SERVER_HELLO = bytes.fromhex("16 0303 007a  02 000076 0303") + bytes(116)
CHANGE_CIPHER_SPEC = bytes.fromhex("14 0303 0001 01")
# 암호화된 HTTP 요청 (TLS 1.3 Application Data), Length 53
APP_DATA = bytes.fromhex("17 0303 0035") + CIPHER[:53]

# 서버의 첫 응답 세그먼트 (MSS 1448바이트): ServerHello + ChangeCipherSpec + 암호화된 Handshake
# (EncryptedExtensions·Certificate…를 담은 Application Data, Length 2426)의 앞 1310바이트
SERVER_FLIGHT = SERVER_HELLO + CHANGE_CIPHER_SPEC + bytes.fromhex("17 0303 097a") + CIPHER[:1310]
# 그다음 세그먼트: 그 Application Data의 나머지 1116바이트 = 레코드 헤더로 시작하지 않음
NEXT_SEGMENT = CIPHER[1310:2426]

KEY = ("10.0.2.15", 51234, "34.223.124.45", 443)


def record(ctype: int, body: bytes, version: int = 0x0303) -> bytes:
    """레코드 헤더(Content Type 1, Version 2, Length 2) + 내용."""
    return struct.pack("!BHH", ctype, version, len(body)) + body


class TestOneRecord(unittest.TestCase):
    def test_client_hello(self):
        app = parse_tls(CLIENT_HELLO)
        self.assertEqual(app.name, "TLS")
        self.assertEqual(app.summary, "TLS record type=22(Handshake) version=TLS 1.0 len=512")
        self.assertEqual(app.lines, [])
        self.assertEqual(app.fields, {
            "records": [{"content_type": 22, "type_name": "Handshake", "version": 0x0301,
                         "version_name": "TLS 1.0", "length": 512, "in_segment": 512}],
            "continues": False})

    def test_server_hello(self):
        app = parse_tls(SERVER_HELLO)
        self.assertEqual(app.summary, "TLS record type=22(Handshake) version=TLS 1.2 len=122")
        self.assertEqual(app.lines, [])

    def test_change_cipher_spec_alert_heartbeat(self):
        self.assertEqual(parse_tls(CHANGE_CIPHER_SPEC).summary,
                         "TLS record type=20(ChangeCipherSpec) version=TLS 1.2 len=1")
        alert = bytes.fromhex("15 0303 0002 0228")          # 암호화 전 Alert: fatal handshake_failure
        self.assertEqual(parse_tls(alert).summary, "TLS record type=21(Alert) version=TLS 1.2 len=2")
        self.assertEqual(parse_tls(record(24, bytes(19))).summary,
                         "TLS record type=24(Heartbeat) version=TLS 1.2 len=19")

    def test_application_data(self):
        app = parse_tls(APP_DATA)
        self.assertEqual(app.summary, "TLS record type=23(Application Data) version=TLS 1.2 len=53")
        self.assertEqual(app.lines, [])
        self.assertFalse(app.fields["continues"])

    def test_versions(self):
        for version, name in ((0x0300, "SSL 3.0"), (0x0301, "TLS 1.0"), (0x0302, "TLS 1.1"),
                              (0x0303, "TLS 1.2"), (0x0304, "TLS 1.3")):
            app = parse_tls(record(23, b"\x80", version))
            self.assertEqual(app.summary, f"TLS record type=23(Application Data) version={name} len=1")
            self.assertEqual(app.fields["records"][0]["version"], version)

    def test_max_record_length(self):
        # Length는 2^14 + 2048 = 18432까지 (암호화된 레코드 최대). 넘으면 레코드 헤더가 아님
        app = parse_tls(bytes.fromhex("17 0303 4800") + CIPHER[:100])
        self.assertEqual(app.fields["records"][0]["length"], 18432)
        self.assertIsNone(parse_tls(bytes.fromhex("17 0303 4801") + CIPHER[:100]))


class TestSeveralRecords(unittest.TestCase):
    def test_server_flight_continues(self):
        app = parse_tls(SERVER_FLIGHT)
        self.assertEqual(app.summary, "TLS record type=22(Handshake) version=TLS 1.2 len=122")
        self.assertEqual(app.lines, [
            "TLS record type=20(ChangeCipherSpec) version=TLS 1.2 len=1",
            "TLS record type=23(Application Data) version=TLS 1.2 len=2426",
            "(레코드가 다음 세그먼트로 이어짐: 이 세그먼트에 1310/2426 bytes)",
        ])
        records = app.fields["records"]
        self.assertEqual([r["type_name"] for r in records],
                         ["Handshake", "ChangeCipherSpec", "Application Data"])
        self.assertEqual([(r["length"], r["in_segment"]) for r in records],
                         [(122, 122), (1, 1), (2426, 1310)])
        self.assertTrue(app.fields["continues"])

    def test_complete_records(self):
        # TLS 1.2 클라이언트: ClientKeyExchange(x25519 공개키) + ChangeCipherSpec + 암호화된 Finished
        cke = bytes.fromhex("16 0303 0025  10 000021 20") + bytes(32)
        finished = bytes.fromhex("16 0303 0028") + CIPHER[:40]
        app = parse_tls(cke + CHANGE_CIPHER_SPEC + finished)
        self.assertEqual(app.summary, "TLS record type=22(Handshake) version=TLS 1.2 len=37")
        self.assertEqual(app.lines, ["TLS record type=20(ChangeCipherSpec) version=TLS 1.2 len=1",
                                     "TLS record type=22(Handshake) version=TLS 1.2 len=40"])
        self.assertFalse(app.fields["continues"])

    def test_big_record_continues(self):
        # 내려받기 중 Application Data 16408바이트(16384 + 태그 등)의 첫 세그먼트
        app = parse_tls(bytes.fromhex("17 0303 4018") + CIPHER[:1443])
        self.assertEqual(app.summary,
                         "TLS record type=23(Application Data) version=TLS 1.2 len=16408")
        self.assertEqual(app.lines, ["(레코드가 다음 세그먼트로 이어짐: 이 세그먼트에 1443/16408 bytes)"])
        self.assertTrue(app.fields["continues"])

    def test_next_header_cut(self):
        # 레코드가 딱 끝나고 다음 레코드 헤더 5바이트 중 3바이트만 이 세그먼트에 있음
        app = parse_tls(APP_DATA + b"\x17\x03\x03")
        self.assertEqual(app.summary, "TLS record type=23(Application Data) version=TLS 1.2 len=53")
        self.assertEqual(app.lines, ["(다음 레코드 헤더가 다음 세그먼트로 이어짐: 이 세그먼트에 3/5 bytes)"])
        self.assertEqual(len(app.fields["records"]), 1)
        self.assertTrue(app.fields["continues"])

    def test_many_records_are_capped(self):
        app = parse_tls(record(23, b"\x80") * 50)
        self.assertEqual(len(app.fields["records"]), 50)
        line = "TLS record type=23(Application Data) version=TLS 1.2 len=1"
        self.assertEqual(app.lines, [line] * (MAX_RECORD_LINES - 1)
                         + [f"… 레코드 {50 - MAX_RECORD_LINES}개 더 (모두 50개)"])


class TestNotRecordStart(unittest.TestCase):
    """레코드 헤더로 시작하지 않으면 None → decode()는 [DATA]로 찍는다."""

    def test_continuation_segment(self):
        self.assertIsNone(parse_tls(NEXT_SEGMENT))

    def test_not_tls(self):
        cases = {
            "빈 데이터": b"",
            "평문 HTTP": b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "SSH": b"SSH-2.0-OpenSSH_9.6\r\n",
            "keep-alive 1바이트": b"\x00",
            "없는 Content Type": bytes.fromhex("19 0303 0010") + bytes(16),
            "없는 Version": bytes.fromhex("17 0309 0010") + bytes(16),
            "DTLS Version (UDP용)": bytes.fromhex("17 fefd 0010") + bytes(16),
            "SSLv2 모양 ClientHello": bytes.fromhex("802e 01 0301 0015 0000 0010"),
        }
        for why, data in cases.items():
            self.assertIsNone(parse_tls(data), why)


class TestBroken(unittest.TestCase):
    def test_short_header(self):
        # 레코드 헤더 모양으로 시작하는데 5바이트가 안 됨
        for data in (b"\x16", b"\x16\x03", b"\x16\x03\x01", b"\x16\x03\x01\x02"):
            with self.assertRaises(ValueError, msg=data.hex()):
                parse_tls(data)

    def test_not_header_after_first_record(self):
        cases = {
            "둘째 Content Type이 아님": CHANGE_CIPHER_SPEC + bytes.fromhex("99 0303 0001 01"),
            "둘째 Version이 아님": CHANGE_CIPHER_SPEC + bytes.fromhex("17 0399 0001 01"),
            "둘째 Length가 너무 김": CHANGE_CIPHER_SPEC + bytes.fromhex("17 0303 ffff") + CIPHER[:10],
            "첫 Length가 짧아 암호문 중간에 떨어짐": bytes.fromhex("17 0303 000a") + CIPHER[:53],
            "잘린 둘째 헤더가 헤더 모양이 아님": CHANGE_CIPHER_SPEC + b"\x99",
            "잘린 둘째 헤더 Version이 아님": CHANGE_CIPHER_SPEC + b"\x17\x05",
        }
        for why, data in cases.items():
            with self.assertRaises(ValueError, msg=why):
                parse_tls(data)


class TestThroughParseApp(unittest.TestCase):
    """parse_app → parse_tls 실제 연결 (mock 없음)."""

    def test_tls_ports(self):
        for port in (443, 465, 993, 995):
            hello = parse_app(KEY, "TCP", 51234, port, CLIENT_HELLO, DEFAULT_PORTS)
            self.assertEqual(hello.summary, "TLS record type=22(Handshake) version=TLS 1.0 len=512")
            flight = parse_app(KEY, "TCP", port, 51234, SERVER_FLIGHT, DEFAULT_PORTS)
            self.assertEqual(len(flight.fields["records"]), 3)
            self.assertIsNone(parse_app(KEY, "TCP", port, 51234, NEXT_SEGMENT, DEFAULT_PORTS))

    def test_not_tls_port(self):
        # TLS 포트가 아니면 레코드 모양이어도 TLS로 고르지 않는다 (--port tls=8443 으로 바꿀 수 있음)
        self.assertIsNone(parse_app(KEY, "TCP", 51234, 8443, CLIENT_HELLO, DEFAULT_PORTS))

    def test_broken_is_value_error(self):
        # parse_app은 ValueError를 그대로 올리고, decode()가 잡아 [DATA]로 둔다
        with self.assertRaises(ValueError):
            parse_app(KEY, "TCP", 51234, 443, b"\x16\x03\x01", DEFAULT_PORTS)


class TestThroughDecode(unittest.TestCase):
    """프레임 → decode() → parse_app → parse_tls → format_packet 화면 줄 (mock 없음)."""

    def run_frame(self, sport, dport, payload, direction):
        from src import output              # A의 파일 — 깨져도 위쪽 parse_tls 테스트는 돌게 여기서 불러옴
        from src.decode import decode
        frame = eth(ipv4(tcp_header(sport, dport, flags=0x18) + payload))      # PSH,ACK
        with contextlib.redirect_stderr(io.StringIO()):
            pkt = decode(Captured(no=1, ts=1.0, direction=direction, frame=frame))
        return pkt, output.format_packet(pkt)

    def test_client_hello_line(self):
        pkt, lines = self.run_frame(51234, 443, CLIENT_HELLO, "OUT")
        self.assertEqual(pkt.app.name, "TLS")
        self.assertIn("  [TLS ] TLS record type=22(Handshake) version=TLS 1.0 len=512", lines)

    def test_server_flight_lines(self):
        _pkt, lines = self.run_frame(443, 51234, SERVER_FLIGHT, "IN")
        start = lines.index("  [TLS ] TLS record type=22(Handshake) version=TLS 1.2 len=122")
        self.assertEqual(lines[start + 1:], [
            "         TLS record type=20(ChangeCipherSpec) version=TLS 1.2 len=1",
            "         TLS record type=23(Application Data) version=TLS 1.2 len=2426",
            "         (레코드가 다음 세그먼트로 이어짐: 이 세그먼트에 1310/2426 bytes)",
        ])

    def test_continuation_is_data(self):
        pkt, lines = self.run_frame(443, 51234, NEXT_SEGMENT, "IN")
        self.assertIsNone(pkt.app)
        self.assertTrue(any(line.startswith("  [DATA] 1116 bytes") for line in lines), lines)


if __name__ == "__main__":
    unittest.main()
