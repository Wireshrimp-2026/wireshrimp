# =============================================================================
# ICMP 해석(parse_icmp) 단위 테스트 (#16)
# - ping과 traceroute(UDP 방식, -I 방식)가 주고받는 모양 그대로의 ICMP 바이트로 확인
#   (체크섬도 실제처럼 계산해서 넣음)
# =============================================================================
import contextlib
import io
import socket
import struct
import unittest

from src.decode.icmp import describe, parse_icmp, type_name
from src.models import Captured
from tests.test_link_ip import eth, ipv4

ME, ROUTER, DST = "10.0.2.15", "10.0.2.2", "34.223.124.45"
KEYS = {"type", "code", "type_name", "checksum", "id", "seq", "orig_src_ip", "orig_dst_ip",
        "orig_proto", "orig_ttl", "orig_src_port", "orig_dst_port", "orig_id", "orig_seq"}


# -----------------------------------------------------------------------------
# 메시지 만들기 도우미 (test_route.py도 씀)
# -----------------------------------------------------------------------------
def checksum(data: bytes) -> int:
    """16비트 1의 보수 합의 보수 (ICMP 체크섬)."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def icmp(icmp_type: int, code: int, rest: bytes = b"\x00" * 4, body: bytes = b"") -> bytes:
    """ICMP 메시지: Type, Code, Checksum(계산), 헤더 나머지 4바이트, 내용."""
    cks = checksum(struct.pack("!BBH", icmp_type, code, 0) + rest + body)
    return struct.pack("!BBH", icmp_type, code, cks) + rest + body


def echo(icmp_type: int, ident: int, seq: int, data: bytes = bytes(range(0x10, 0x38))) -> bytes:
    """Echo Request(8)·Reply(0). 기본 데이터 40바이트 (traceroute -I와 같은 길이)."""
    return icmp(icmp_type, 0, struct.pack("!HH", ident, seq), data)


def ip_header(proto: int, src: str, dst: str, ttl: int, payload_len: int,
              flags_frag: int = 0x0000, options: bytes = b"") -> bytes:
    ihl = 5 + len(options) // 4
    return struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, ihl * 4 + payload_len, 0x1c2d,
                       flags_frag, ttl, proto, 0, socket.inet_aton(src),
                       socket.inet_aton(dst)) + options


def udp_probe_quote(dport: int, ttl: int = 1, dst: str = DST, sport: int = 40001) -> bytes:
    """오류 메시지에 담기는 traceroute UDP 프로브: 원본 IP 헤더 + UDP 헤더 8바이트 (데이터 32바이트는 뺌)."""
    return ip_header(17, ME, dst, ttl, 8 + 32) + struct.pack("!HHHH", sport, dport, 40, 0x5d3c)


def echo_probe_quote(ident: int, seq: int, ttl: int = 1, dst: str = DST) -> bytes:
    """오류 메시지에 담기는 traceroute -I 프로브: 원본 IP 헤더 + Echo Request 앞 8바이트."""
    return ip_header(1, ME, dst, ttl, 8 + 40) + echo(8, ident, seq)[:8]


# 라우터 → 나: traceroute 프로브(TTL 1, 40001 → 33434)의 TTL이 다 됨
TIME_EXCEEDED = icmp(11, 0, body=udp_probe_quote(33434))
# 목적지 → 나: 프로브가 도착했는데 그 포트에 프로그램이 없음 (원본 TTL은 도착 때 남은 값)
PORT_UNREACHABLE = icmp(3, 3, body=udp_probe_quote(33468, ttl=1))
# 라우터 → 나: traceroute -I 프로브(Echo Request id=0x1c2d seq=5)의 TTL이 다 됨
TIME_EXCEEDED_ECHO = icmp(11, 0, body=echo_probe_quote(0x1c2d, 5))


class TestEcho(unittest.TestCase):
    def test_ping_request(self):
        data = echo(8, 0x1c2d, 1)
        info = parse_icmp(data)
        self.assertEqual(set(info), KEYS)                   # 늘 같은 키, 해당 없는 값은 None
        self.assertEqual((info["type"], info["code"], info["type_name"]), (8, 0, "Echo Request"))
        self.assertEqual((info["id"], info["seq"]), (0x1c2d, 1))
        self.assertEqual(info["checksum"], struct.unpack_from("!H", data, 2)[0])
        self.assertTrue(all(info[k] is None for k in KEYS if k.startswith("orig_")))

    def test_ping_reply(self):
        info = parse_icmp(echo(0, 0x1c2d, 1))
        self.assertEqual((info["type"], info["type_name"], info["id"], info["seq"]),
                         (0, "Echo Reply", 0x1c2d, 1))

    def test_echo_without_data(self):
        info = parse_icmp(echo(8, 7, 65535, data=b""))     # 헤더 8바이트만
        self.assertEqual((info["id"], info["seq"]), (7, 65535))


class TestErrors(unittest.TestCase):
    def test_time_exceeded_udp_probe(self):
        info = parse_icmp(TIME_EXCEEDED)
        self.assertEqual((info["type"], info["code"], info["type_name"]), (11, 0, "Time Exceeded"))
        self.assertEqual((info["orig_src_ip"], info["orig_dst_ip"], info["orig_proto"], info["orig_ttl"]),
                         (ME, DST, 17, 1))
        self.assertEqual((info["orig_src_port"], info["orig_dst_port"]), (40001, 33434))
        self.assertEqual((info["id"], info["seq"], info["orig_id"], info["orig_seq"]),
                         (None, None, None, None))

    def test_port_unreachable(self):
        info = parse_icmp(PORT_UNREACHABLE)
        self.assertEqual(info["type_name"], "Destination Unreachable (Port Unreachable)")
        self.assertEqual((info["orig_dst_ip"], info["orig_dst_port"]), (DST, 33468))

    def test_time_exceeded_echo_probe(self):
        # traceroute -I: 안에 담긴 원본이 Echo Request → 짝 맞추기용 orig_id·orig_seq (#18)
        info = parse_icmp(TIME_EXCEEDED_ECHO)
        self.assertEqual((info["orig_proto"], info["orig_id"], info["orig_seq"]), (1, 0x1c2d, 5))
        self.assertEqual((info["orig_src_port"], info["orig_dst_port"]), (None, None))

    def test_router_quotes_whole_probe(self):
        # 리눅스 라우터는 8바이트보다 많이(원본 전체) 담아 보낸다
        whole = udp_probe_quote(33435) + bytes(32)
        info = parse_icmp(icmp(11, 0, body=whole))
        self.assertEqual(info["orig_dst_port"], 33435)

    def test_tcp_quote(self):
        # Fragmentation Needed (경로 MTU 찾기): 헤더 나머지 = 0000 + 다음 홉 MTU, 원본은 TCP
        quote = ip_header(6, ME, DST, 63, 20) + struct.pack("!HHI", 51234, 443, 1000)
        info = parse_icmp(icmp(3, 4, struct.pack("!HH", 0, 1500), quote))
        self.assertEqual(info["type_name"], "Destination Unreachable (Fragmentation Needed)")
        self.assertEqual((info["orig_proto"], info["orig_src_port"], info["orig_dst_port"]),
                         (6, 51234, 443))

    def test_quote_with_ip_options(self):
        quote = ip_header(17, ME, DST, 1, 8, options=b"\x01\x01\x01\x00") + struct.pack("!HHHH", 1, 33434, 8, 0)
        self.assertEqual(parse_icmp(icmp(11, 0, body=quote))["orig_dst_port"], 33434)

    def test_quote_without_ports(self):
        cases = {
            "원본이 두 번째 이후 조각": ip_header(17, ME, DST, 1, 8, flags_frag=0x00b9) + bytes(8),
            "IP 헤더 뒤가 2바이트뿐": ip_header(17, ME, DST, 1, 8) + b"\x9c\x41",
            "원본 ICMP가 Echo가 아님": ip_header(1, ME, DST, 1, 8) + icmp(3, 3)[:8],
        }
        for why, quote in cases.items():
            info = parse_icmp(icmp(11, 0, body=quote))
            self.assertEqual(info["orig_dst_ip"], DST, why)
            self.assertEqual((info["orig_src_port"], info["orig_dst_port"], info["orig_id"],
                              info["orig_seq"]), (None, None, None, None), why)


class TestNames(unittest.TestCase):
    def test_type_name(self):
        self.assertEqual(type_name(3, 13), "Destination Unreachable (Communication Prohibited)")
        self.assertEqual(type_name(3, 99), "Destination Unreachable")
        self.assertEqual(type_name(11, 1), "Time Exceeded")
        self.assertIsNone(type_name(42, 0))                  # 모르는 Type
        self.assertIsNone(parse_icmp(icmp(42, 0))["type_name"])

    def test_describe_for_hop_table(self):
        # DESIGN 4.3 홉 표의 ICMP 칸
        self.assertEqual(describe(11, 0), "11/0 Time Exceeded")
        self.assertEqual(describe(3, 3), "3/3 Port Unreachable")
        self.assertEqual(describe(0, 0), "0/0 Echo Reply")
        self.assertEqual(describe(3, 99), "3/99 Destination Unreachable")
        self.assertEqual(describe(42, 1), "42/1")


class TestBroken(unittest.TestCase):
    def test_value_errors(self):
        cases = {
            "빈 데이터": b"",
            "헤더 8바이트 미만": echo(8, 1, 1)[:7],
            "원본 IP 헤더가 20바이트 미만": icmp(11, 0, body=udp_probe_quote(33434)[:19]),
            "원본 IP 헤더가 아예 없음": icmp(3, 3),
            "원본이 IPv4가 아님": icmp(11, 0, body=b"\x60" + udp_probe_quote(33434)[1:]),
            "원본 IHL이 5 미만": icmp(11, 0, body=b"\x44" + udp_probe_quote(33434)[1:]),
            "원본 IP 옵션이 잘림": icmp(11, 0, body=b"\x46" + udp_probe_quote(33434)[1:20]),
        }
        for why, data in cases.items():
            with self.assertRaises(ValueError, msg=why):
                parse_icmp(data)


class TestThroughDecode(unittest.TestCase):
    """프레임 → decode() → parse_icmp → format_packet 화면 줄 (mock 없음)."""

    def run_frame(self, message, src=ROUTER, dst=ME, direction="IN"):
        from src import output              # A의 파일 — 깨져도 위쪽 parse_icmp 테스트는 돌게 여기서 불러옴
        from src.decode import decode
        frame = eth(ipv4(message, proto=1, src=src, dst=dst))
        with contextlib.redirect_stderr(io.StringIO()):
            pkt = decode(Captured(no=1, ts=1.0, direction=direction, frame=frame))
        return pkt, output.format_packet(pkt)

    def test_time_exceeded_lines(self):
        pkt, lines = self.run_frame(TIME_EXCEEDED)
        self.assertEqual(pkt.icmp, parse_icmp(TIME_EXCEEDED))
        cks = struct.unpack_from("!H", TIME_EXCEEDED, 2)[0]
        self.assertIn(f"  [ICMP] type=11 code=0 Time Exceeded cksum=0x{cks:04x}", lines)
        self.assertIn("         orig: 10.0.2.15 -> 34.223.124.45 proto=17 ttl=1 port 40001 -> 33434",
                      lines)

    def test_port_unreachable_and_echo_lines(self):
        _pkt, lines = self.run_frame(PORT_UNREACHABLE, src=DST)
        self.assertTrue(any(line.startswith("  [ICMP] type=3 code=3 Destination Unreachable "
                                            "(Port Unreachable) cksum=") for line in lines), lines)
        _pkt, lines = self.run_frame(echo(8, 0x1c2d, 1), src=ME, dst=DST, direction="OUT")
        self.assertTrue(any(line.startswith("  [ICMP] type=8 code=0 Echo Request cksum=")
                            and line.endswith(" id=7213 seq=1") for line in lines), lines)

    def test_broken_icmp_does_not_stop_decode(self):
        pkt, _lines = self.run_frame(icmp(11, 0, body=b"\x45\x00"))
        self.assertIsNone(pkt.icmp)                # ValueError는 decode()가 잡아 ICMP 계층만 None
        self.assertEqual(pkt.proto, "ICMP")


if __name__ == "__main__":
    unittest.main()
