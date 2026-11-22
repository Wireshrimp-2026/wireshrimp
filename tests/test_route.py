# =============================================================================
# traceroute 홉 표(RouteTracker) 단위 테스트 (#16)
# - traceroute(UDP 방식)·traceroute -I(ICMP 방식)가 주고받는 순서대로 PacketInfo를 넣어 확인
#   (ICMP 응답은 test_icmp.py의 실제 모양 바이트를 parse_icmp로 풀어서 넣음)
# - 마지막에는 프레임 → decode() → RouteTracker → format_route 홉 표까지
# =============================================================================
import contextlib
import io
import struct
import unittest

from src.decode.icmp import parse_icmp
from src.models import Captured, PacketInfo
from src.route import ECHO_PROBE_MAX_TTL, RouteTracker
from tests.test_icmp import DST, ME, ROUTER, echo, echo_probe_quote, icmp, udp_probe_quote
from tests.test_link_ip import eth, ipv4

ROUTER2 = "192.168.0.1"
IDENT = 0x1c2d                 # traceroute -I 의 Echo id
T0 = 1000.0


# -----------------------------------------------------------------------------
# 패킷 만들기 도우미
# -----------------------------------------------------------------------------
def packet(direction, src, dst, ts, ttl=64, udp=None, icmp_info=None, proto=None):
    proto = proto or ("UDP" if udp else "ICMP")
    return PacketInfo(no=0, ts=ts, direction=direction, frame_len=0, eth={},
                      ip={"src_ip": src, "dst_ip": dst, "ttl": ttl}, proto=proto,
                      udp=udp, icmp=icmp_info)


def udp_probe(ttl, port, ts, dst=DST):
    """OUT: traceroute UDP 프로브 (IP TTL = 홉 번호)."""
    return packet("OUT", ME, dst, ts, ttl, udp={"src_port": 40001, "dst_port": port})


def udp_reply(router, port, ts, icmp_type=11, code=0, dst=DST):
    """IN: 프로브에 대한 ICMP 오류 (라우터의 Time Exceeded, 목적지의 Port Unreachable 등)."""
    message = icmp(icmp_type, code, body=udp_probe_quote(port, dst=dst))
    return packet("IN", router, ME, ts, icmp_info=parse_icmp(message))


def echo_probe(ttl, seq, ts, ident=IDENT):
    """OUT: traceroute -I 프로브 (Echo Request)."""
    return packet("OUT", ME, DST, ts, ttl, icmp_info=parse_icmp(echo(8, ident, seq)))


def echo_time_exceeded(router, seq, ts):
    return packet("IN", router, ME, ts, icmp_info=parse_icmp(icmp(11, 0, body=echo_probe_quote(IDENT, seq))))


def echo_reply(seq, ts, ident=IDENT):
    return packet("IN", DST, ME, ts, icmp_info=parse_icmp(echo(0, ident, seq)))


def run(packets):
    tracker = RouteTracker()
    for p in packets:
        tracker.add(p)
    return rounded(tracker.hops())


def rounded(hops):
    """RTT 소수 오차 정리 (0.39999… → 0.4)."""
    return {dst: [(n, ip, [None if r is None else round(r, 3) for r in rtts], desc)
                  for n, ip, rtts, desc in table]
            for dst, table in hops.items()}


class TestUdpTraceroute(unittest.TestCase):
    def test_hops_like_design_example(self):
        # DESIGN 4.3 모양: 1홉 라우터, 2홉 무응답, 3홉 목적지 도착 (traceroute -q 3, 포트는 프로브마다 +1)
        packets, port = [], 33434
        for ttl, router, rtts, icmp_type, code in ((1, ROUTER, [0.4, 0.3, 0.3], 11, 0),
                                                   (2, None, [None, None, None], None, None),
                                                   (3, DST, [151.0, 150.2, None], 3, 3)):
            for rtt in rtts:
                sent = T0 + (port - 33434) * 0.01
                packets.append(udp_probe(ttl, port, sent))
                if rtt is not None:
                    packets.append(udp_reply(router, port, sent + rtt / 1000, icmp_type, code))
                port += 1
        self.assertEqual(run(packets), {DST: [
            (1, ROUTER, [0.4, 0.3, 0.3], "11/0 Time Exceeded"),
            (2, None, [None, None, None], None),
            (3, DST, [151.0, 150.2, None], "3/3 Port Unreachable"),
        ]})

    def test_probes_sent_together_stop_at_arrival(self):
        # traceroute는 여러 TTL을 한꺼번에 보냄 → 3홉 목적지가 TTL 3·4·5 프로브에 모두 응답
        # 응답 순서도 섞여서 옴. 홉 표는 처음 도착한 3홉까지
        packets = [udp_probe(ttl, 33433 + ttl, T0) for ttl in range(1, 6)]
        packets += [udp_reply(DST, 33438, T0 + 0.0301, 3, 3), udp_reply(DST, 33436, T0 + 0.0302, 3, 3),
                    udp_reply(ROUTER, 33434, T0 + 0.0005), udp_reply(DST, 33437, T0 + 0.0303, 3, 3),
                    udp_reply(ROUTER2, 33435, T0 + 0.002)]
        self.assertEqual(run(packets), {DST: [
            (1, ROUTER, [0.5], "11/0 Time Exceeded"),
            (2, ROUTER2, [2.0], "11/0 Time Exceeded"),
            (3, DST, [30.2], "3/3 Port Unreachable"),
        ]})

    def test_no_arrival_shows_all_probed_hops(self):
        packets = [udp_probe(1, 33434, T0), udp_reply(ROUTER, 33434, T0 + 0.001),
                   udp_probe(2, 33435, T0), udp_probe(3, 33436, T0)]
        self.assertEqual(run(packets), {DST: [(1, ROUTER, [1.0], "11/0 Time Exceeded"),
                                              (2, None, [None], None),
                                              (3, None, [None], None)]})

    def test_unreachable_from_router_ends_path(self):
        # 중간 방화벽이 막음 (3/13) → 거기가 경로 끝
        packets = [udp_probe(ttl, 33433 + ttl, T0) for ttl in (1, 2, 3)]
        packets += [udp_reply(ROUTER, 33434, T0 + 0.001), udp_reply(ROUTER2, 33435, T0 + 0.002, 3, 13)]
        self.assertEqual(run(packets), {DST: [(1, ROUTER, [1.0], "11/0 Time Exceeded"),
                                              (2, ROUTER2, [2.0], "3/13 Communication Prohibited")]})

    def test_several_routers_on_one_hop(self):
        # 경로 부하 분산: 같은 홉의 프로브에 다른 라우터가 응답 → 처음 응답한 라우터, RTT는 모두
        packets = [udp_probe(1, 33434, T0), udp_reply(ROUTER2, 33434, T0 + 0.003),
                   udp_probe(1, 33435, T0 + 0.01), udp_reply(ROUTER, 33435, T0 + 0.014)]
        self.assertEqual(run(packets)[DST], [(1, ROUTER2, [3.0, 4.0], "11/0 Time Exceeded")])

    def test_duplicate_and_unmatched_replies_are_ignored(self):
        packets = [udp_probe(1, 33434, T0), udp_reply(ROUTER, 33434, T0 + 0.005),
                   udp_reply(ROUTER, 33434, T0 + 0.009),                  # 같은 프로브에 두 번째 응답
                   udp_reply(ROUTER, 33500, T0 + 0.001),                  # 보낸 적 없는 프로브
                   udp_reply(ROUTER, 33434, T0 + 0.001, dst="8.8.8.8")]   # 다른 목적지로 간 프로브
        self.assertEqual(run(packets), {DST: [(1, ROUTER, [5.0], "11/0 Time Exceeded")]})

    def test_traceroute_run_twice(self):
        # 같은 목적지로 다시 실행하면 같은 포트를 다시 씀 → 새 프로브와 짝, RTT가 이어 붙음
        packets = [udp_probe(1, 33434, T0), udp_reply(ROUTER, 33434, T0 + 0.001),
                   udp_probe(1, 33434, T0 + 5), udp_reply(ROUTER, 33434, T0 + 5.002)]
        self.assertEqual(run(packets)[DST], [(1, ROUTER, [1.0, 2.0], "11/0 Time Exceeded")])

    def test_two_destinations(self):
        packets = [udp_probe(1, 33434, T0, dst="8.8.8.8"), udp_probe(1, 33434, T0),
                   udp_reply(ROUTER, 33434, T0 + 0.001),
                   udp_reply(ROUTER, 33434, T0 + 0.002, dst="8.8.8.8")]
        hops = run(packets)
        self.assertEqual(list(hops), ["8.8.8.8", DST])              # 처음 프로브를 본 순서
        self.assertEqual(hops["8.8.8.8"], [(1, ROUTER, [2.0], "11/0 Time Exceeded")])
        self.assertEqual(hops[DST], [(1, ROUTER, [1.0], "11/0 Time Exceeded")])


class TestIcmpTraceroute(unittest.TestCase):
    def test_traceroute_dash_i(self):
        # sudo traceroute -I: Echo Request id 고정, seq는 프로브마다 +1
        packets, seq = [], 1
        for ttl in (1, 2, 3):
            for _ in range(3):
                sent = T0 + seq * 0.01
                packets.append(echo_probe(ttl, seq, sent))
                if ttl == 1:
                    packets.append(echo_time_exceeded(ROUTER, seq, sent + 0.0004))
                elif ttl == 3:
                    packets.append(echo_reply(seq, sent + 0.151))
                seq += 1
        self.assertEqual(run(packets), {DST: [
            (1, ROUTER, [0.4, 0.4, 0.4], "11/0 Time Exceeded"),
            (2, None, [None, None, None], None),
            (3, DST, [151.0, 151.0, 151.0], "0/0 Echo Reply"),
        ]})

    def test_ping_is_not_a_probe(self):
        # ping은 TTL 64(리눅스 기본) → 프로브가 아님. ECHO_PROBE_MAX_TTL까지는 프로브
        self.assertEqual(run([echo_probe(64, 1, T0), echo_reply(1, T0 + 0.02)]), {})
        hops = run([echo_probe(ECHO_PROBE_MAX_TTL, 1, T0), echo_reply(1, T0 + 0.02)])
        self.assertEqual(hops[DST], [(ECHO_PROBE_MAX_TTL, DST, [20.0], "0/0 Echo Reply")])

    def test_other_echo_id_does_not_match(self):
        packets = [echo_probe(1, 1, T0), echo_reply(1, T0 + 0.01, ident=0x9999)]
        self.assertEqual(run(packets), {DST: [(1, None, [None], None)]})


class TestOtherPackets(unittest.TestCase):
    def test_ignored_without_error(self):
        # main은 NotImplementedError만 잡으므로 add()는 어떤 패킷에도 예외를 내면 안 됨
        others = [
            packet("OUT", ME, "8.8.8.8", T0, udp={"src_port": 40000, "dst_port": 53}),      # DNS
            PacketInfo(no=0, ts=T0, direction="OUT", frame_len=0, eth={}, proto="TCP",
                       ip={"src_ip": ME, "dst_ip": DST, "ttl": 64},
                       tcp={"src_port": 51234, "dst_port": 80}),
            packet("IN", DST, ME, T0, ttl=1, udp={"src_port": 40001, "dst_port": 33434}),  # 남이 보낸 프로브
            packet("OUT", ME, DST, T0, icmp_info=parse_icmp(icmp(3, 3, body=udp_probe_quote(33434)))),
            packet("IN", ROUTER, ME, T0, proto="ICMP"),            # parse_icmp가 실패해 icmp=None
            PacketInfo(no=0, ts=T0, direction="IN", frame_len=0, eth={}, proto="OTHER",
                       ip={"src_ip": ROUTER, "dst_ip": ME, "ttl": 64}),
        ]
        tracker = RouteTracker()
        for p in others:
            tracker.add(p)
        self.assertEqual(tracker.hops(), {})


class TestThroughDecode(unittest.TestCase):
    """프레임 → decode() → RouteTracker → format_route 홉 표 (mock 없음)."""

    def test_udp_traceroute_table(self):
        from src import output              # A의 파일 — 깨져도 위쪽 테스트는 돌게 여기서 불러옴
        from src.decode import decode

        def captured(no, ts, direction, ip_packet):
            with contextlib.redirect_stderr(io.StringIO()):
                return decode(Captured(no=no, ts=ts, direction=direction, frame=eth(ip_packet)))

        def probe(ttl, port):
            udp = struct.pack("!HHHH", 40001, port, 40, 0) + bytes(32)
            return ipv4(udp, proto=17, src=ME, dst=DST, ttl=ttl)

        def reply(src, icmp_type, code, port):
            return ipv4(icmp(icmp_type, code, body=udp_probe_quote(port)), proto=1, src=src, dst=ME)

        tracker = RouteTracker()
        for pkt in (captured(1, T0, "OUT", probe(1, 33434)),
                    captured(2, T0 + 0.0004, "IN", reply(ROUTER, 11, 0, 33434)),
                    captured(3, T0 + 0.01, "OUT", probe(2, 33435)),
                    captured(4, T0 + 0.02, "OUT", probe(3, 33436)),
                    captured(5, T0 + 0.171, "IN", reply(DST, 3, 3, 33436))):
            tracker.add(pkt)
        lines = output.format_route(DST, tracker.hops()[DST])
        self.assertEqual(lines[0], "[ROUTE] -> 34.223.124.45")
        self.assertEqual([line.split() for line in lines[2:]], [
            ["1", "10.0.2.2", "0.4", "ms", "11/0", "Time", "Exceeded"],
            ["2", "*", "*", "(응답", "없음)"],
            ["3", "34.223.124.45", "151.0", "ms", "3/3", "Port", "Unreachable", "(도착)"],
        ])


if __name__ == "__main__":
    unittest.main()
