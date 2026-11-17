# =============================================================================
# 담당자  : A
# 맡은 기능: F1 캡처 필터(frame_matches) 단위 테스트 — 실제 소켓 없이 프레임 바이트로 확인
# 완료 기준: DNS·HTTP·ICMP·traceroute 프로브만 남고 나머지는 버려진다.
# =============================================================================
import struct
import unittest

from src.capture import CaptureFilter, frame_matches
from tests.test_link_ip import eth, ipv4, tcp_header


def udp(sport: int, dport: int) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8, 0)


class TestFrameMatches(unittest.TestCase):
    def setUp(self):
        self.f = CaptureFilter(iface="eth0")

    def test_http_and_dns_kept(self):
        self.assertTrue(frame_matches(eth(ipv4(tcp_header(51234, 80))), self.f))
        self.assertTrue(frame_matches(eth(ipv4(tcp_header(80, 51234))), self.f))
        self.assertTrue(frame_matches(eth(ipv4(udp(40000, 53), proto=17)), self.f))

    def test_other_ports_dropped(self):
        self.assertFalse(frame_matches(eth(ipv4(tcp_header(51234, 443))), self.f))
        self.assertFalse(frame_matches(eth(ipv4(udp(5353, 5353), proto=17)), self.f))

    def test_icmp(self):
        frame = eth(ipv4(b"\x0b\x00\x00\x00", proto=1))
        self.assertTrue(frame_matches(frame, self.f))
        self.assertFalse(frame_matches(frame, CaptureFilter(allow_icmp=False)))

    def test_traceroute_probe(self):
        self.assertTrue(frame_matches(eth(ipv4(udp(40001, 33434), proto=17)), self.f))
        self.assertTrue(frame_matches(eth(ipv4(udp(40001, 33534), proto=17)), self.f))
        self.assertFalse(frame_matches(eth(ipv4(udp(40001, 33535), proto=17)), self.f))

    def test_server_ips(self):
        f = CaptureFilter(server_ips=["34.223.124.45"])
        self.assertTrue(frame_matches(eth(ipv4(tcp_header(51234, 80))), f))
        self.assertFalse(frame_matches(eth(ipv4(tcp_header(51234, 80), dst="1.2.3.4")), f))
        # DNS는 대상 서버가 아니어도 남긴다
        self.assertTrue(frame_matches(eth(ipv4(udp(40000, 53), proto=17, dst="8.8.8.8")), f))

    def test_non_ipv4_and_short(self):
        self.assertFalse(frame_matches(eth(b"\x60" + b"\x00" * 39, ethertype=0x86DD), self.f))
        self.assertFalse(frame_matches(b"\x00" * 10, self.f))
        self.assertFalse(frame_matches(eth(ipv4(b"\x00\x50", proto=6)), self.f))

    def test_vlan(self):
        self.assertTrue(frame_matches(eth(ipv4(tcp_header(51234, 80)), vlan=True), self.f))


if __name__ == "__main__":
    unittest.main()
