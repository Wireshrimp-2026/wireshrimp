# =============================================================================
# 응용 프로토콜 판별(parse_app) 단위 테스트 — HTTP·DNS 분기 (#10), TLS 분기 (#13)
# 하위 파서(parse_http, parse_dns, parse_tls)는 mock으로 바꿔 "어느 파서를 어떤 인자로 불렀나"만 본다
# =============================================================================
import contextlib
import io
import struct
import unittest
from unittest import mock

from src.decode.app_select import looks_like_http, match_port, parse_app
from src.models import DEFAULT_PORTS, AppInfo, Captured
from tests.test_link_ip import eth, ipv4, tcp_header

KEY = ("10.0.2.15", 51234, "34.223.124.45", 80)
DNS_APP = AppInfo("DNS", "Standard query 0x1a2b A neverssl.com")
HTTP_APP = AppInfo("HTTP", "GET / HTTP/1.1", lines=["Host: neverssl.com"])
TLS_APP = AppInfo("TLS", "TLS record type=22(Handshake) version=TLS 1.0 len=512")
GET = b"GET / HTTP/1.1\r\nHost: neverssl.com\r\n\r\n"
CLIENT_HELLO = b"\x16\x03\x01\x02\x00"         # 레코드 헤더: Handshake, TLS 1.0, 512
SERVER_HELLO = b"\x16\x03\x03\x00\x7a"         # 레코드 헤더: Handshake, TLS 1.2, 122


def patch_dns(**kw):
    return mock.patch("src.decode.app_dns.parse_dns", **({"return_value": DNS_APP} | kw))


def patch_http(**kw):
    return mock.patch("src.decode.app_http.parse_http", **({"return_value": HTTP_APP} | kw))


def patch_tls(**kw):
    return mock.patch("src.decode.app_tls.parse_tls", **({"return_value": TLS_APP} | kw))


def app(proto, sport, dport, payload, ports=DEFAULT_PORTS):
    return parse_app(KEY, proto, sport, dport, payload, ports)


def cli_ports(port_option):
    """main.py가 --port 옵션을 해석한 포트 표 그대로 (main.py가 깨져도 다른 테스트는 돌게 여기서 불러옴)."""
    from src.main import parse_args
    return parse_args(["--iface", "eth0", "--port", port_option]).ports


class TestDns(unittest.TestCase):
    def test_udp_query_and_response(self):
        with patch_dns() as pd:
            self.assertIs(app("UDP", 40000, 53, b"\x1a\x2b"), DNS_APP)   # 질의
            pd.assert_called_with(b"\x1a\x2b", over_tcp=False)
            self.assertIs(app("UDP", 53, 40000, b"\x1a\x2b"), DNS_APP)   # 응답
            self.assertEqual(pd.call_count, 2)

    def test_tcp_dns_sets_over_tcp(self):
        with patch_dns() as pd:
            self.assertIs(app("TCP", 51000, 53, b"\x00\x1c\x1a\x2b"), DNS_APP)
        pd.assert_called_once_with(b"\x00\x1c\x1a\x2b", over_tcp=True)

    def test_broken_dns_raises_value_error(self):
        # 깨진 데이터의 ValueError는 그대로 올린다 → decode()가 잡아 app=None
        with patch_dns(side_effect=ValueError("short")):
            with self.assertRaises(ValueError):
                app("UDP", 40000, 53, b"\x00")


class TestHttp(unittest.TestCase):
    def test_http_ports_both_directions(self):
        with patch_http() as ph:
            self.assertIs(app("TCP", 51234, 80, GET), HTTP_APP)
            self.assertIs(app("TCP", 8080, 51234, b"HTTP/1.1 200 OK\r\n\r\n"), HTTP_APP)
        self.assertEqual(ph.call_count, 2)
        ph.assert_any_call(GET)

    def test_http_by_content_on_other_port(self):
        with patch_http() as ph:
            self.assertIs(app("TCP", 51234, 3000, GET), HTTP_APP)
            self.assertIs(app("TCP", 3000, 51234, b"HTTP/1.0 404 Not Found\r\n"), HTTP_APP)
            self.assertIsNone(app("TCP", 51234, 3000, b"\x16\x03\x01\x02\x00"))   # TLS 같은 바이너리
        self.assertEqual(ph.call_count, 2)

    def test_continuation_on_http_port(self):
        # HTTP 포트인데 첫 줄이 HTTP가 아님 = 응답 본문이 이어지는 세그먼트 → continuation
        with patch_http(return_value=None):
            cont = app("TCP", 80, 51234, b"<html>...</html>")
            self.assertEqual((cont.name, cont.summary), ("HTTP", "continuation 16 bytes"))
            self.assertTrue(cont.fields["continuation"])
            # HTTP 포트가 아니면(내용만 보고 골랐는데 아니었음) continuation으로 만들지 않는다
            self.assertIsNone(app("TCP", 51234, 3000, b"GET broken"))


class TestTls(unittest.TestCase):
    def test_tls_ports_both_directions(self):
        with patch_tls() as pt:
            for port in (443, 465, 993, 995):
                self.assertIs(app("TCP", 51234, port, CLIENT_HELLO), TLS_APP)     # 클라이언트 → 서버
                self.assertIs(app("TCP", port, 51234, SERVER_HELLO), TLS_APP)     # 서버 → 클라이언트
        self.assertEqual(pt.call_count, 8)
        pt.assert_any_call(CLIENT_HELLO)
        pt.assert_any_call(SERVER_HELLO)

    def test_record_continuation_is_none(self):
        # 레코드 헤더로 시작하지 않는 세그먼트 → parse_tls가 None → 그대로 None ([DATA])
        with patch_tls(return_value=None) as pt:
            self.assertIsNone(app("TCP", 443, 51234, b"\x9e\x9f\xa0\xa1"))
        pt.assert_called_once_with(b"\x9e\x9f\xa0\xa1")

    def test_port_override(self):
        ports = cli_ports("tls=8443")
        self.assertEqual(ports["tls"], (8443,))
        with patch_tls() as pt:
            self.assertIsNone(app("TCP", 51234, 443, CLIENT_HELLO, ports))       # 443은 이제 TLS 아님
            pt.assert_not_called()
            self.assertIs(app("TCP", 51234, 8443, CLIENT_HELLO, ports), TLS_APP)
            self.assertIs(app("TCP", 8443, 51234, SERVER_HELLO, ports), TLS_APP)
        self.assertEqual(pt.call_count, 2)

    def test_port_in_both_tls_and_http(self):
        # --port tls=8080 처럼 한 포트가 http·tls 둘 다에 들면 TLS (TLS 데이터를 HTTP continuation으로 찍지 않게)
        ports = cli_ports("tls=8080")
        with patch_tls() as pt, patch_http() as ph:
            self.assertIs(app("TCP", 51234, 8080, CLIENT_HELLO, ports), TLS_APP)
        pt.assert_called_once_with(CLIENT_HELLO)
        ph.assert_not_called()

    def test_plain_http_and_udp_on_443(self):
        with patch_tls() as pt, patch_http() as ph:
            # 평문 HTTP 요청줄은 TLS 포트여도 내용으로 HTTP (TLS 레코드는 20~24로 시작해 겹치지 않음)
            self.assertIs(app("TCP", 51234, 443, GET), HTTP_APP)
            # UDP 443은 QUIC — TLS 레코드가 아님
            self.assertIsNone(app("UDP", 51234, 443, CLIENT_HELLO))
        pt.assert_not_called()
        ph.assert_called_once_with(GET)


class TestPortTable(unittest.TestCase):
    def test_port_override(self):
        ports = dict(DEFAULT_PORTS) | {"http": (8000,)}           # --port http=8000
        with patch_http() as ph:
            self.assertIsNone(app("TCP", 51234, 80, b"\x00\x01", ports))
            ph.assert_not_called()
            self.assertIs(app("TCP", 51234, 8000, b"\x00\x01", ports), HTTP_APP)

    def test_destination_port_first(self):
        self.assertEqual(match_port(("dns", "http"), DEFAULT_PORTS, 53, 80), "http")
        self.assertEqual(match_port(("dns", "http"), DEFAULT_PORTS, 80, 53), "dns")
        self.assertEqual(match_port(("dns", "http"), DEFAULT_PORTS, 8080, 51234), "http")
        self.assertIsNone(match_port(("dns", "http"), DEFAULT_PORTS, 51234, 443))

    def test_not_application_layer(self):
        with patch_dns() as pd, patch_http() as ph:
            self.assertIsNone(app("UDP", 40001, 33434, b"probe"))     # traceroute 프로브
            self.assertIsNone(app("UDP", 5353, 5353, b"\x00\x00"))    # mDNS
            self.assertIsNone(app("UDP", 40000, 80, GET))             # HTTP는 TCP만
            self.assertIsNone(app("TCP", 51234, 80, b""))             # 빈 페이로드
            self.assertIsNone(app("ICMP", 0, 0, b"x"))
        pd.assert_not_called()
        ph.assert_not_called()

    def test_looks_like_http(self):
        for start in (b"GET /", b"POST /x", b"HEAD /", b"HTTP/1.1 200 OK", b"OPTIONS * HTTP/1.1"):
            self.assertTrue(looks_like_http(start), start)
        for other in (b"GETX", b"get / HTTP/1.1", b"EHLO x", b"+OK", b"\x13BitTorrent"):
            self.assertFalse(looks_like_http(other), other)


class TestAppInfoShape(unittest.TestCase):
    """하위 파서가 형식을 어기면 출력 단계가 아니라 여기서 TypeError (decode가 잡음)."""

    def test_bad_shapes(self):
        bad = [
            AppInfo("DNS", "q", lines=[b"bytes line"]),
            AppInfo("DNS", "q", lines=["ok", 3]),
            AppInfo("DNS", "q", lines="not a list"),
            AppInfo("DNS", None),
            AppInfo("DNS", "q", fields=[]),
            ("DNS", "q"),
        ]
        for value in bad:
            with patch_dns(return_value=value), self.assertRaises(TypeError, msg=repr(value)):
                app("UDP", 40000, 53, b"\x1a\x2b")

    def test_good_shape(self):
        good = AppInfo("DNS", "q", lines=["a", "b"], fields={"txid": 1})
        with patch_dns(return_value=good):
            self.assertIs(app("UDP", 40000, 53, b"\x1a\x2b"), good)


class TestThroughDecode(unittest.TestCase):
    """실제 프레임 → decode() → parse_udp/parse_tcp(A) → parse_app → (mock) 파서."""

    def decode(self, frame):
        from src.decode import decode
        with contextlib.redirect_stderr(io.StringIO()):
            return decode(Captured(no=1, ts=1.0, direction="OUT", frame=frame))

    def udp_frame(self, sport, dport, data):
        hdr = struct.pack("!HHHH", sport, dport, 8 + len(data), 0)     # 체크섬 0 = 안 씀
        return eth(ipv4(hdr + data, proto=17, dst="8.8.8.8"))

    def test_dns_over_udp(self):
        with patch_dns() as pd:
            pkt = self.decode(self.udp_frame(40000, 53, b"\x1a\x2bquery"))
        self.assertIs(pkt.app, DNS_APP)
        pd.assert_called_once_with(b"\x1a\x2bquery", over_tcp=False)

    def test_http_over_tcp(self):
        frame = eth(ipv4(tcp_header(51234, 80, flags=0x18) + GET))     # PSH,ACK
        with patch_http() as ph:
            pkt = self.decode(frame)
        self.assertIs(pkt.app, HTTP_APP)
        ph.assert_called_once_with(GET)

    def test_bad_shape_does_not_stop_decode(self):
        with patch_dns(return_value=AppInfo("DNS", "q", lines=[b"x"])):
            pkt = self.decode(self.udp_frame(40000, 53, b"\x1a\x2b"))
        self.assertIsNone(pkt.app)               # 형식이 틀린 결과는 버리고
        self.assertEqual(pkt.udp["dst_port"], 53)  # 나머지 계층은 그대로
        self.assertEqual(pkt.payload, b"\x1a\x2b")


if __name__ == "__main__":
    unittest.main()
