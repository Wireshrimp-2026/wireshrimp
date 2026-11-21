# =============================================================================
# 캡처 필터(frame_matches) 단위 테스트 — 실제 소켓 없이 프레임 바이트로 확인
# =============================================================================
import struct
import unittest

from src.capture import CaptureFilter, frame_matches
from tests.test_link_ip import eth, ipv4, tcp_header


def udp(sport: int, dport: int) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8, 0)


class TestFrameMatches(unittest.TestCase):
    def setUp(self):
        self.f = CaptureFilter(iface="eth0", protos=frozenset({"http", "dns", "traceroute"}))

    def test_http_and_dns_kept(self):
        self.assertTrue(frame_matches(eth(ipv4(tcp_header(51234, 80))), self.f))
        self.assertTrue(frame_matches(eth(ipv4(tcp_header(80, 51234))), self.f))
        self.assertTrue(frame_matches(eth(ipv4(udp(40000, 53), proto=17)), self.f))

    def test_other_ports_dropped(self):
        self.assertFalse(frame_matches(eth(ipv4(tcp_header(51234, 443))), self.f))
        self.assertFalse(frame_matches(eth(ipv4(udp(5353, 5353), proto=17)), self.f))

    def test_mail_ports_by_proto(self):
        f = CaptureFilter(protos=frozenset({"smtp", "pop3", "imap"}))
        for port in (25, 587, 110, 143):
            self.assertTrue(frame_matches(eth(ipv4(tcp_header(51234, port))), f))
        self.assertFalse(frame_matches(eth(ipv4(tcp_header(51234, 80))), f))
        f2 = CaptureFilter(protos=frozenset({"smtp"}), ports={"smtp": (2525,)})
        self.assertTrue(frame_matches(eth(ipv4(tcp_header(51234, 2525))), f2))
        self.assertFalse(frame_matches(eth(ipv4(tcp_header(51234, 25))), f2))

    def test_icmp_only_with_traceroute(self):
        frame = eth(ipv4(b"\x0b\x00\x00\x00", proto=1))
        self.assertTrue(frame_matches(frame, self.f))
        self.assertFalse(frame_matches(frame, CaptureFilter(protos=frozenset({"http"}))))

    def test_traceroute_probe(self):
        self.assertTrue(frame_matches(eth(ipv4(udp(40001, 33434), proto=17)), self.f))
        self.assertTrue(frame_matches(eth(ipv4(udp(40001, 33534), proto=17)), self.f))
        self.assertFalse(frame_matches(eth(ipv4(udp(40001, 33535), proto=17)), self.f))

    def test_bittorrent_keeps_any_port(self):
        f = CaptureFilter(protos=frozenset({"bittorrent"}))
        self.assertTrue(frame_matches(eth(ipv4(tcp_header(51234, 51413))), f))
        self.assertTrue(frame_matches(eth(ipv4(udp(6881, 6881), proto=17)), f))

    def test_hosts(self):
        f = CaptureFilter(protos=frozenset({"http", "dns"}), hosts=["34.223.124.45"])
        self.assertTrue(frame_matches(eth(ipv4(tcp_header(51234, 80))), f))
        self.assertFalse(frame_matches(eth(ipv4(tcp_header(51234, 80), dst="1.2.3.4")), f))
        # DNS는 hosts와 상관없이 남긴다
        self.assertTrue(frame_matches(eth(ipv4(udp(40000, 53), proto=17, dst="8.8.8.8")), f))

    def test_non_ipv4_and_short(self):
        self.assertFalse(frame_matches(eth(b"\x60" + b"\x00" * 39, ethertype=0x86DD), self.f))
        self.assertFalse(frame_matches(b"\x00" * 10, self.f))
        self.assertFalse(frame_matches(eth(ipv4(b"\x00\x50", proto=6)), self.f))

    def test_vlan(self):
        self.assertTrue(frame_matches(eth(ipv4(tcp_header(51234, 80)), vlan=True), self.f))


if __name__ == "__main__":
    unittest.main()
