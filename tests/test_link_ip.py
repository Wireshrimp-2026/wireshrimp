# =============================================================================
# Ethernet·IP 파싱, decode() 단위 테스트 (샘플: tests/samples/)
# =============================================================================
import contextlib
import io
import socket
import struct
import unittest

from src.decode.link_ip import ip_checksum, parse_ethernet, parse_ip
from src.models import Captured

SRC_MAC = bytes.fromhex("080027aabbcc")
DST_MAC = bytes.fromhex("5254001234ff")


def eth(payload: bytes, ethertype: int = 0x0800, vlan: bool = False) -> bytes:
    hdr = DST_MAC + SRC_MAC
    if vlan:
        hdr += struct.pack("!HH", 0x8100, 0x0064)
    return hdr + struct.pack("!H", ethertype) + payload


def ipv4(payload: bytes, proto: int = 6, src: str = "10.0.2.15", dst: str = "34.223.124.45",
         ttl: int = 64, options: bytes = b"", flags_frag: int = 0x4000) -> bytes:
    ihl = 5 + len(options) // 4
    total = ihl * 4 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, total, 0x1234, flags_frag,
                      ttl, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + options + payload


def tcp_header(sport: int = 51234, dport: int = 80, flags: int = 0x02) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 5 << 4, flags, 64240, 0, 0)


class TestParseEthernet(unittest.TestCase):
    def test_basic(self):
        info, ethertype, rest = parse_ethernet(eth(b"\x45abc"))
        self.assertEqual(info["src_mac"], "08:00:27:aa:bb:cc")
        self.assertEqual(info["dst_mac"], "52:54:00:12:34:ff")
        self.assertEqual(ethertype, 0x0800)
        self.assertEqual(info["ethertype"], 0x0800)
        self.assertIsNone(info["vlan"])
        self.assertEqual(rest, b"\x45abc")

    def test_vlan(self):
        info, ethertype, rest = parse_ethernet(eth(b"xyz", vlan=True))
        self.assertEqual(info["vlan"], 100)
        self.assertEqual(ethertype, 0x0800)
        self.assertEqual(rest, b"xyz")

    def test_ipv6_ethertype(self):
        _info, ethertype, _rest = parse_ethernet(eth(b"", ethertype=0x86DD))
        self.assertEqual(ethertype, 0x86DD)

    def test_too_short(self):
        with self.assertRaises(ValueError):
            parse_ethernet(b"\x00" * 13)


class TestParseIp(unittest.TestCase):
    def test_basic(self):
        info, rest = parse_ip(ipv4(b"PAYLOAD", proto=17, ttl=117))
        self.assertEqual(info["version"], 4)
        self.assertEqual(info["ihl"], 5)
        self.assertEqual(info["ttl"], 117)
        self.assertEqual(info["protocol"], 17)
        self.assertEqual(info["proto_name"], "UDP")
        self.assertEqual(info["src_ip"], "10.0.2.15")
        self.assertEqual(info["dst_ip"], "34.223.124.45")
        self.assertTrue(info["df"])
        self.assertFalse(info["mf"])
        self.assertEqual(info["frag_offset"], 0)
        self.assertEqual(rest, b"PAYLOAD")

    def test_options(self):
        info, rest = parse_ip(ipv4(b"data", options=b"\x01\x01\x01\x00"))
        self.assertEqual(info["header_len"], 24)
        self.assertEqual(rest, b"data")

    def test_ethernet_padding_removed(self):
        # 60바이트 최소 프레임을 채우려고 붙은 0 padding은 페이로드에서 빠져야 한다.
        _info, rest = parse_ip(ipv4(b"ab") + b"\x00" * 6)
        self.assertEqual(rest, b"ab")

    def test_checksum(self):
        hdr = bytearray(ipv4(b""))
        info, _ = parse_ip(bytes(hdr))
        self.assertFalse(info["checksum_ok"])          # 체크섬 0으로 만든 헤더
        hdr[10:12] = struct.pack("!H", ip_checksum(bytes(hdr[:20])))
        info, _ = parse_ip(bytes(hdr))
        self.assertTrue(info["checksum_ok"])

    def test_unknown_proto(self):
        info, _rest = parse_ip(ipv4(b"", proto=47))
        self.assertEqual(info["proto_name"], "OTHER")

    def test_fragment_offset(self):
        info, _rest = parse_ip(ipv4(b"x", flags_frag=0x2000 | 185))
        self.assertTrue(info["more_fragments"])
        self.assertEqual(info["frag_offset"], 185 * 8)

    def test_errors(self):
        with self.assertRaises(ValueError):
            parse_ip(b"\x45" * 19)                       # 너무 짧음
        bad_version = bytearray(ipv4(b""))
        bad_version[0] = 0x65
        with self.assertRaises(ValueError):
            parse_ip(bytes(bad_version))                 # IPv6
        bad_ihl = bytearray(ipv4(b""))
        bad_ihl[0] = 0x44
        with self.assertRaises(ValueError):
            parse_ip(bytes(bad_ihl))                     # IHL < 5
        with self.assertRaises(ValueError):
            parse_ip(ipv4(b"", options=b"\x01" * 4)[:22])  # 옵션이 잘림


class TestDecode(unittest.TestCase):
    """하위 파서가 미구현이거나 실패해도 Ethernet·IP 필드는 채워져야 한다."""

    def decode(self, frame: bytes, direction: str = "OUT"):
        from src.decode import decode
        with contextlib.redirect_stderr(io.StringIO()):
            return decode(Captured(no=7, ts=1.5, direction=direction, frame=frame))

    def test_tcp_frame_ip_fields(self):
        frame = eth(ipv4(tcp_header(), proto=6, ttl=64))
        pkt = self.decode(frame)
        self.assertIsNotNone(pkt)
        self.assertEqual((pkt.no, pkt.ts, pkt.direction), (7, 1.5, "OUT"))
        self.assertEqual(pkt.frame_len, len(frame))
        self.assertEqual(pkt.eth["src_mac"], "08:00:27:aa:bb:cc")
        self.assertEqual(pkt.eth["dst_mac"], "52:54:00:12:34:ff")
        self.assertEqual(pkt.src_ip, "10.0.2.15")
        self.assertEqual(pkt.dst_ip, "34.223.124.45")
        self.assertEqual(pkt.ip["ttl"], 64)
        self.assertEqual(pkt.proto, "TCP")

    def test_icmp_and_other(self):
        self.assertEqual(self.decode(eth(ipv4(b"\x0b\x00" + b"\x00" * 6, proto=1))).proto, "ICMP")
        other = self.decode(eth(ipv4(b"abcd", proto=47)))
        self.assertEqual(other.proto, "OTHER")
        self.assertEqual(other.payload, b"abcd")

    def test_not_ipv4(self):
        self.assertIsNone(self.decode(eth(b"\x60" + b"\x00" * 39, ethertype=0x86DD)))
        self.assertIsNone(self.decode(eth(b"\x00" * 28, ethertype=0x0806)))   # ARP
        self.assertIsNone(self.decode(b"\x00" * 10))
        self.assertIsNone(self.decode(eth(b"\x45\x00")))                       # IP 잘림

    def test_broken_transport_does_not_crash(self):
        pkt = self.decode(eth(ipv4(b"\x00\x50", proto=6)))   # TCP 헤더 2바이트뿐
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.proto, "TCP")
        self.assertIsNone(pkt.tcp)

    def test_tcp_result_and_app_dispatch(self):
        from unittest import mock
        from src.models import AppInfo
        fields = {"src_port": 51234, "dst_port": 80, "flags": "ACK,PSH", "seq": 1000, "ack": 1}
        app = AppInfo(name="HTTP", summary="GET / HTTP/1.1")
        with mock.patch("src.decode.transport.parse_tcp", return_value=(fields, b"GET / HTTP/1.1\r\n")), \
             mock.patch("src.decode.app_select.parse_app", return_value=app) as pa:
            pkt = self.decode(eth(ipv4(tcp_header())))
        self.assertEqual(pkt.tcp, fields)
        self.assertEqual((pkt.src_port, pkt.dst_port), (51234, 80))
        self.assertEqual(pkt.payload, b"GET / HTTP/1.1\r\n")
        self.assertIs(pkt.app, app)
        key, proto, sport, dport, payload, _ports = pa.call_args.args
        self.assertEqual(key, ("10.0.2.15", 51234, "34.223.124.45", 80))
        self.assertEqual((proto, sport, dport), ("TCP", 51234, 80))

    def test_no_app_call_without_payload(self):
        from unittest import mock
        fields = {"src_port": 51234, "dst_port": 80, "flags": "SYN"}
        with mock.patch("src.decode.transport.parse_tcp", return_value=(fields, b"")), \
             mock.patch("src.decode.app_select.parse_app") as pa:
            pkt = self.decode(eth(ipv4(tcp_header())))
        pa.assert_not_called()
        self.assertIsNone(pkt.app)

    def test_udp_and_icmp_results(self):
        from unittest import mock
        udp = {"src_port": 40000, "dst_port": 53, "length": 14, "checksum": 0}
        with mock.patch("src.decode.transport.parse_udp", return_value=(udp, b"DNSMSG")) as pu, \
             mock.patch("src.decode.app_select.parse_app", return_value=None):
            pkt = self.decode(eth(ipv4(b"\x00" * 8, proto=17)))
        # 체크섬 검증용 의사 헤더를 만들 IP 주소가 함께 넘어가야 한다
        pu.assert_called_once_with(b"\x00" * 8, "10.0.2.15", "34.223.124.45")
        self.assertEqual(pkt.udp, udp)
        self.assertEqual(pkt.payload, b"DNSMSG")

        icmp = {"type": 11, "code": 0}
        with mock.patch("src.decode.icmp.parse_icmp", return_value=icmp):
            pkt = self.decode(eth(ipv4(b"\x0b\x00" + b"\x00" * 6, proto=1)), direction="IN")
        self.assertEqual(pkt.icmp, icmp)

    def test_wrong_shape_from_subparser_does_not_crash(self):
        from unittest import mock
        for bad in ({"src_port": 1}, ({"src_port": 1},), ("x", b""), ({"x": 1}, b""), None):
            with mock.patch("src.decode.transport.parse_tcp", return_value=bad):
                pkt = self.decode(eth(ipv4(tcp_header())))
            self.assertIsNotNone(pkt)
            self.assertEqual(pkt.ip["ttl"], 64)
            self.assertIsNone(pkt.tcp)
            self.assertIsNone(pkt.src_port)


if __name__ == "__main__":
    unittest.main()
