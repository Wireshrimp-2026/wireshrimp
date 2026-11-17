# =============================================================================
# 담당자  : A
# 맡은 기능: Ethernet·IP 파싱, decode() 단위 테스트 (샘플: tests/samples/)
# 완료 기준: IP·TTL이 Wireshark와 일치한다.
# =============================================================================
import contextlib
import io
import socket
import struct
import unittest

from src.decode.link_ip import parse_ethernet, parse_ip
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
        self.assertEqual(rest, b"\x45abc")

    def test_vlan(self):
        _info, ethertype, rest = parse_ethernet(eth(b"xyz", vlan=True))
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
        self.assertTrue(info["dont_fragment"])
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
    """하위 파서(B·C·D)가 미구현이거나 실패해도 A 필드는 채워져야 한다."""

    def decode(self, frame: bytes, direction: str = "OUT"):
        from src.decode import decode
        with contextlib.redirect_stderr(io.StringIO()):
            return decode(Captured(ts=1.5, direction=direction, frame=frame))

    def test_tcp_frame_a_fields(self):
        pkt = self.decode(eth(ipv4(tcp_header(), proto=6, ttl=64)))
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.ts, 1.5)
        self.assertEqual(pkt.direction, "OUT")
        self.assertEqual(pkt.src_mac, "08:00:27:aa:bb:cc")
        self.assertEqual(pkt.dst_mac, "52:54:00:12:34:ff")
        self.assertEqual(pkt.src_ip, "10.0.2.15")
        self.assertEqual(pkt.dst_ip, "34.223.124.45")
        self.assertEqual(pkt.ttl, 64)
        self.assertEqual(pkt.proto, "TCP")

    def test_icmp_and_other(self):
        self.assertEqual(self.decode(eth(ipv4(b"\x0b\x00" + b"\x00" * 6, proto=1))).proto, "ICMP")
        other = self.decode(eth(ipv4(b"abcd", proto=47)))
        self.assertEqual(other.proto, "OTHER")
        self.assertEqual(other.payload_len, 4)

    def test_not_ipv4(self):
        self.assertIsNone(self.decode(eth(b"\x60" + b"\x00" * 39, ethertype=0x86DD)))
        self.assertIsNone(self.decode(eth(b"\x00" * 28, ethertype=0x0806)))   # ARP
        self.assertIsNone(self.decode(b"\x00" * 10))
        self.assertIsNone(self.decode(eth(b"\x45\x00")))                       # IP 잘림

    def test_broken_transport_does_not_crash(self):
        pkt = self.decode(eth(ipv4(b"\x00\x50", proto=6)))   # TCP 헤더 2바이트뿐
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.proto, "TCP")

    def test_subparser_results_merged(self):
        from unittest import mock
        fields = {"src_port": 51234, "dst_port": 80, "tcp_flags": "SYN", "seq": 1000,
                  "ack": 0, "window": 64240, "data_offset": 20}
        with mock.patch("src.decode.transport.parse_tcp", return_value=(fields, b"")):
            pkt = self.decode(eth(ipv4(tcp_header())))
        self.assertEqual((pkt.src_port, pkt.dst_port), (51234, 80))
        self.assertEqual(pkt.tcp_flags, "SYN")
        self.assertEqual(pkt.window, 64240)
        self.assertEqual(pkt.payload_len, 0)
        self.assertIsNone(pkt.http)

    def test_wrong_shape_from_subparser_does_not_crash(self):
        from unittest import mock
        for bad in ({"src_port": 1}, ({"src_port": 1},), ("x", b""), None):
            with mock.patch("src.decode.transport.parse_tcp", return_value=bad):
                pkt = self.decode(eth(ipv4(tcp_header())))
            self.assertIsNotNone(pkt)
            self.assertEqual(pkt.ttl, 64)
            self.assertIsNone(pkt.src_port)

    def test_dns_and_http_dispatch(self):
        from unittest import mock
        udp = {"src_port": 40000, "dst_port": 53, "udp_length": 20}
        with mock.patch("src.decode.transport.parse_udp", return_value=(udp, b"DNSMSG")), \
             mock.patch("src.decode.app_dns.parse_dns", return_value="dns!") as pd:
            pkt = self.decode(eth(ipv4(b"\x00" * 8, proto=17)))
        pd.assert_called_once_with(b"DNSMSG")
        self.assertEqual(pkt.dns, "dns!")
        self.assertEqual(pkt.payload_len, 6)

        tcp = {"src_port": 80, "dst_port": 51234, "tcp_flags": "PSH,ACK"}
        with mock.patch("src.decode.transport.parse_tcp", return_value=(tcp, b"HTTP/1.1 200 OK\r\n")), \
             mock.patch("src.decode.app_http.parse_http", return_value="http!") as ph:
            pkt = self.decode(eth(ipv4(tcp_header())), direction="IN")
        ph.assert_called_once()
        self.assertEqual(pkt.http, "http!")


if __name__ == "__main__":
    unittest.main()
