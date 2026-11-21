# =============================================================================
# 출력 형식 단위 테스트 — 4.1 패킷, 4.2 연결 요약, 4.3 홉 표, 로그 파일
# =============================================================================
import contextlib
import io
import os
import tempfile
import unittest

from src import output
from src.models import AppInfo, Connection, PacketInfo
from tests.test_tcp_track import curl_session

IP = {"version": 4, "header_len": 20, "tos": 0, "total_length": 132, "id": 0x1c2d, "df": True,
      "mf": False, "frag_offset": 0, "ttl": 64, "protocol": 6, "checksum": 0x8a1f,
      "checksum_ok": True, "src_ip": "10.0.2.15", "dst_ip": "34.223.124.45"}
ETH = {"src_mac": "08:00:27:aa:bb:cc", "dst_mac": "52:54:00:12:35:02", "ethertype": 0x0800,
       "vlan": None}


def http_pkt(**kw):
    p = PacketInfo(no=12, ts=1700000000.5, direction="OUT", frame_len=132, eth=ETH, ip=dict(IP),
                   proto="TCP",
                   tcp={"src_port": 51234, "dst_port": 80, "seq": 3021457731, "ack": 1874020011,
                        "header_len": 32, "flags": "ACK,PSH", "flag_bits": 0x18, "window": 502,
                        "checksum": 0x4c2e, "urgent": 0, "options": ["NOP", "NOP", "TS val=1 ecr=2"]},
                   payload=b"GET / HTTP/1.1\r\n", rel_seq=1, rel_ack=1,
                   app=AppInfo("HTTP", "GET / HTTP/1.1", ["Host: neverssl.com"]),
                   frame=bytes(range(20)))
    for k, v in kw.items():
        setattr(p, k, v)
    return p


class TestFormatPacket(unittest.TestCase):
    def test_tcp_http(self):
        lines = output.format_packet(http_pkt())
        self.assertRegex(lines[0], r"^#12 +\d\d:\d\d:\d\d\.500000  OUT  TCP  "
                                   r"10\.0\.2\.15:51234 -> 34\.223\.124\.45:80  len=132$")
        text = "\n".join(lines)
        self.assertIn("[ETH ] dst=52:54:00:12:35:02 src=08:00:27:aa:bb:cc type=0x0800(IPv4)", text)
        self.assertIn("flags=DF frag=0 ttl=64 proto=6(TCP) cksum=0x8a1f(ok)", text)
        self.assertIn("src=10.0.2.15 dst=34.223.124.45", text)
        self.assertIn("seq=1 ack=1 (raw seq=3021457731 ack=1874020011)", text)
        self.assertIn("hlen=32 flags=ACK,PSH win=502 cksum=0x4c2e urg=0 opts=[NOP, NOP, TS val=1 ecr=2]", text)
        self.assertIn("  [HTTP] GET / HTTP/1.1", text)
        self.assertIn("         Host: neverssl.com", text)

    def test_checksum_notes(self):
        ip = dict(IP, checksum_ok=False)
        self.assertIn("(offload)", "\n".join(output.format_packet(http_pkt(ip=ip))))
        self.assertIn("(bad)", "\n".join(output.format_packet(http_pkt(ip=ip, direction="IN"))))

    def test_udp_and_data(self):
        p = http_pkt(proto="UDP", tcp=None, app=None, payload=b"\xab" * 40, direction="IN",
                     udp={"src_port": 53, "dst_port": 40000, "length": 48, "checksum": 0x1234,
                          "checksum_ok": None})
        text = "\n".join(output.format_packet(p))
        self.assertIn("[UDP ] sport=53 dport=40000 len=48 cksum=0x1234(unchecked)", text)
        p.udp = dict(p.udp, checksum=0)
        self.assertIn("cksum=0x0000(unused)", "\n".join(output.format_packet(p)))
        p.udp = dict(p.udp, checksum=0x1471, checksum_ok=False, checksum_partial=True)
        self.assertIn("cksum=0x1471(offload)", "\n".join(output.format_packet(p)))
        p.udp = dict(p.udp, checksum_partial=False)
        self.assertIn("cksum=0x1471(bad)", "\n".join(output.format_packet(p)))
        self.assertIn("[DATA] 40 bytes  ab ab", text)
        self.assertIn("…", text)

    def test_icmp(self):
        p = http_pkt(proto="ICMP", tcp=None, app=None, payload=b"", direction="IN",
                     icmp={"type": 11, "code": 0, "type_name": "Time Exceeded", "checksum": 0xf4ff,
                           "orig_src_ip": "10.0.2.15", "orig_dst_ip": "34.223.124.45",
                           "orig_proto": 17, "orig_ttl": 1, "orig_src_port": 40001,
                           "orig_dst_port": 33434})
        text = "\n".join(output.format_packet(p))
        self.assertIn("[ICMP] type=11 code=0 Time Exceeded cksum=0xf4ff", text)
        self.assertIn("orig: 10.0.2.15 -> 34.223.124.45 proto=17 ttl=1 port 40001 -> 33434", text)

    def test_no_rel_seq_and_hex(self):
        lines = output.format_packet(http_pkt(rel_seq=None, rel_ack=None), hex=True)
        text = "\n".join(lines)
        self.assertIn("seq=3021457731 ack=1874020011", text)
        self.assertNotIn("raw seq", text)
        self.assertIn("0000  00 01 02 03", text)
        self.assertIn("0010  10 11 12 13", text)


class TestFormatConnection(unittest.TestCase):
    def test_closed_connection(self):
        from src.tcp_track import TcpTracker
        t = TcpTracker()
        conn = [c for p in curl_session() if (c := t.add(p))][0]
        text = "\n".join(output.format_connection(conn))
        self.assertIn("[CONN] 10.0.2.15:51234 <-> 34.223.124.45:80  (HTTP)", text)
        self.assertIn("연결설정  #", text)
        self.assertIn("(3-way handshake 완료)", text)
        self.assertIn("OUT 1개 세그먼트 38 bytes / IN 2개 세그먼트 1,500 bytes", text)
        self.assertIn("(정상 종료)", text)

    def test_opened_before_capture_and_still_open(self):
        conn = Connection(key=("10.0.2.15", 5000, "1.2.3.4", 80), state="ESTABLISHED")
        text = "\n".join(output.format_connection(conn))
        self.assertIn("(캡처 전에 열림)", text)
        self.assertIn("(캡처 종료까지 열려 있음)", text)
        self.assertIn("(TCP)", text)


class TestFormatRoute(unittest.TestCase):
    def test_table(self):
        hops = [(1, "10.0.2.2", [0.4, 0.3, 0.3], "11/0 Time Exceeded"),
                (2, None, [None, None, None], None),
                (3, "34.223.124.45", [151.0, None], "3/3 Port Unreachable")]
        lines = output.format_route("34.223.124.45", hops)
        self.assertEqual(lines[0], "[ROUTE] -> 34.223.124.45")
        self.assertIn("rtt1", lines[1])
        self.assertIn("    1  10.0.2.2         0.4 ms   0.3 ms   0.3 ms   11/0 Time Exceeded", lines)
        self.assertIn("(응답 없음)", lines[3])
        self.assertIn("151.0 ms *", lines[4])
        self.assertTrue(lines[4].endswith("3/3 Port Unreachable (도착)"))


class TestLog(unittest.TestCase):
    def test_screen_and_log_match(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.txt")
            output.open_log(path)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                output.print_packet(http_pkt())
                output.print_route("1.1.1.1", [])
            output.close_log()
            output.close_log()
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read(), buf.getvalue())
        self.assertIn("[HTTP]", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
