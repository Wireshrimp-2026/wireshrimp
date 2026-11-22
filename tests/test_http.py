# =============================================================================
# HTTP 해석(parse_http) 단위 테스트 (#11) — curl·서버가 보내는 모양 그대로의 바이트로 확인
# =============================================================================
import unittest

from src.decode.app_http import MAX_SHOW, http_continuation, parse_http
from src.decode.app_select import parse_app
from src.models import DEFAULT_PORTS

CURL_GET = (b"GET / HTTP/1.1\r\n"
            b"Host: neverssl.com\r\n"
            b"User-Agent: curl/8.5.0\r\n"
            b"Accept: */*\r\n"
            b"\r\n")

RESPONSE = (b"HTTP/1.1 200 OK\r\n"
            b"Date: Sun, 22 Nov 2026 05:03:11 GMT\r\n"
            b"Server: Apache/2.4.62 ()\r\n"
            b"Content-Type: text/html; charset=UTF-8\r\n"
            b"Content-Length: 18\r\n"
            b"\r\n"
            b"<html>hello</html>")


class TestRequest(unittest.TestCase):
    def test_curl_get(self):
        app = parse_http(CURL_GET)
        self.assertEqual(app.name, "HTTP")
        self.assertEqual(app.summary, "GET / HTTP/1.1")
        self.assertEqual(app.lines, ["Host: neverssl.com", "User-Agent: curl/8.5.0", "Accept: */*"])
        f = app.fields
        self.assertTrue(f["is_request"])
        self.assertEqual((f["method"], f["uri"], f["version"]), ("GET", "/", "HTTP/1.1"))
        self.assertIsNone(f["status_code"])
        self.assertEqual(f["headers"]["Host"], "neverssl.com")
        self.assertEqual(f["body_len"], 0)
        self.assertTrue(f["headers_complete"])

    def test_post_with_body(self):
        data = (b"POST /login?next=%2F HTTP/1.1\r\nHost: example.com\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\n"
                b"id=a&pw=b12")
        app = parse_http(data)
        self.assertEqual(app.fields["method"], "POST")
        self.assertEqual(app.fields["uri"], "/login?next=%2F")
        self.assertEqual(app.fields["body_len"], 11)
        self.assertEqual(app.lines[-1], "body: 11 bytes")
        self.assertNotIn("id=a", "\n".join(app.lines))      # 본문 내용은 찍지 않는다

    def test_other_methods_and_http10(self):
        for first in (b"HEAD /x HTTP/1.0", b"OPTIONS * HTTP/1.1", b"DELETE /a/b HTTP/1.1"):
            app = parse_http(first + b"\r\n\r\n")
            self.assertEqual(app.summary, first.decode())
            self.assertEqual(app.fields["method"], first.split()[0].decode())


class TestResponse(unittest.TestCase):
    def test_200_with_body(self):
        app = parse_http(RESPONSE)
        self.assertEqual(app.summary, "HTTP/1.1 200 OK")
        f = app.fields
        self.assertFalse(f["is_request"])
        self.assertEqual((f["version"], f["status_code"], f["reason"]), ("HTTP/1.1", 200, "OK"))
        self.assertIsNone(f["method"])
        self.assertEqual(f["headers"]["Content-Length"], "18")
        self.assertEqual(f["headers"]["Content-Type"], "text/html; charset=UTF-8")
        self.assertEqual(app.lines[0], "Date: Sun, 22 Nov 2026 05:03:11 GMT")
        self.assertEqual(app.lines[-1], "body: 18 bytes")
        self.assertEqual(f["body_len"], 18)

    def test_status_variants(self):
        app = parse_http(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual((app.fields["status_code"], app.fields["reason"]), (404, "Not Found"))
        self.assertNotIn("body: 0 bytes", app.lines)          # 본문이 없으면 body 줄도 없음
        app = parse_http(b"HTTP/1.1 204\r\n\r\n")              # Reason Phrase는 비어도 됨
        self.assertEqual((app.fields["status_code"], app.fields["reason"]), (204, ""))
        app = parse_http(b"HTTP/1.0 301 Moved Permanently\r\nLocation: http://a/\r\n\r\n")
        self.assertEqual(app.fields["headers"]["Location"], "http://a/")


class TestHeaders(unittest.TestCase):
    def test_headers_continue_in_next_segment(self):
        app = parse_http(b"GET / HTTP/1.1\r\nHost: neverssl.com\r\nUser-Ag")
        self.assertFalse(app.fields["headers_complete"])
        self.assertEqual(app.fields["headers"]["Host"], "neverssl.com")
        self.assertEqual(app.lines[-1], "(헤더가 다음 세그먼트로 이어짐)")

    def test_duplicate_headers(self):
        app = parse_http(b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n")
        self.assertEqual(app.fields["headers"]["Set-Cookie"], "a=1, b=2")
        self.assertEqual(app.lines, ["Set-Cookie: a=1", "Set-Cookie: b=2"])

    def test_folded_header_and_odd_lines(self):
        app = parse_http(b"GET / HTTP/1.1\r\nX-Long: part1\r\n  part2\r\nno colon here\r\n\r\n")
        self.assertEqual(app.fields["headers"]["X-Long"], "part1 part2")
        self.assertEqual(app.lines, ["X-Long: part1 part2", "no colon here"])

    def test_bare_newlines(self):
        app = parse_http(b"GET / HTTP/1.1\nHost: a\n\nbody")
        self.assertEqual(app.lines, ["Host: a", "body: 4 bytes"])

    def test_control_chars_and_long_values_are_safe_to_print(self):
        evil = b"GET / HTTP/1.1\r\nX-Evil: \x1b[2J\x1b[31mred\x07\r\nCookie: " + b"c" * 500 + b"\r\n\r\n"
        app = parse_http(evil)
        self.assertEqual(app.lines[0], "X-Evil: \\x1b[2J\\x1b[31mred\\x07")   # 터미널 제어 문자 무력화
        self.assertTrue(app.lines[1].endswith("…"))
        self.assertEqual(len(app.lines[1]), MAX_SHOW + 1)
        self.assertEqual(len(app.fields["headers"]["Cookie"]), 500)          # fields에는 원래 값

    def test_non_ascii_does_not_fail(self):
        app = parse_http("HTTP/1.1 200 OK\r\nX-Name: 새우\r\n\r\n".encode() + b"\xff\xfe")
        self.assertEqual(app.fields["headers"]["X-Name"], "새우")
        self.assertEqual(app.fields["body_len"], 2)


class TestNotHttp(unittest.TestCase):
    def test_returns_none(self):
        for data in (b"", b"<html><body>continued</body></html>", b"\x16\x03\x01\x00\xa5",
                     b"get / HTTP/1.1\r\n\r\n", b"GET /\r\n\r\n", b"GET / HTTP/x\r\n\r\n",
                     b"HTTP/1.1 OK\r\n\r\n", b"HTTP/1.1 2000 OK\r\n\r\n", b"EHLO mail.test\r\n"):
            self.assertIsNone(parse_http(data), data)

    def test_continuation(self):
        app = http_continuation(b"x" * 1448)
        self.assertEqual((app.name, app.summary, app.lines), ("HTTP", "continuation 1448 bytes", []))
        self.assertEqual(app.fields["body_len"], 1448)


class TestThroughParseApp(unittest.TestCase):
    """parse_app → parse_http 실제 연결 (mock 없음)."""

    def run_app(self, sport, dport, data):
        return parse_app(("10.0.2.15", 51234, "34.223.124.45", 80), "TCP", sport, dport,
                         data, DEFAULT_PORTS)

    def test_request_response_and_continuation(self):
        self.assertEqual(self.run_app(51234, 80, CURL_GET).summary, "GET / HTTP/1.1")
        self.assertEqual(self.run_app(80, 51234, RESPONSE).summary, "HTTP/1.1 200 OK")
        self.assertEqual(self.run_app(80, 51234, b"more body bytes").summary,
                         "continuation 15 bytes")

    def test_http_on_other_port_by_content(self):
        self.assertEqual(self.run_app(51234, 3000, CURL_GET).fields["method"], "GET")
        self.assertIsNone(self.run_app(51234, 3000, b"binary\x00data"))


if __name__ == "__main__":
    unittest.main()
