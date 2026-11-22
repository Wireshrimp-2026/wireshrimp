# =============================================================================
# TCP 연결 추적 단위 테스트 — 손으로 만든 PacketInfo로 연결 1개를 흘려 본다
# =============================================================================
import unittest

from src.models import AppInfo, PacketInfo
from src.tcp_track import TcpTracker

CLIENT = ("10.0.2.15", 51234)
SERVER = ("34.223.124.45", 80)
FLAGS = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08, "ACK": 0x10}
ISN_C, ISN_S = 3_000_000_000, 4_294_967_000      # 서버 ISN은 일부러 2^32 근처 (wrap 확인)

_no = 0


def seg(frm, flags, seq, ack=0, payload=b"", app=None):
    global _no
    _no += 1
    src, dst = (CLIENT, SERVER) if frm == "c" else (SERVER, CLIENT)
    bits = sum(FLAGS[f] for f in flags.split(",")) if flags else 0
    return PacketInfo(
        no=_no, ts=float(_no), direction="OUT" if frm == "c" else "IN", frame_len=60,
        eth={}, ip={"src_ip": src[0], "dst_ip": dst[0], "ttl": 64}, proto="TCP",
        tcp={"src_port": src[1], "dst_port": dst[1], "seq": seq % 2**32, "ack": ack % 2**32,
             "flags": flags, "flag_bits": bits},
        payload=payload, app=app)


def curl_session(fin_style=4):
    """SYN → SYN,ACK → ACK → GET → 응답 2개 → FIN 교환."""
    req = b"GET / HTTP/1.1\r\nHost: neverssl.com\r\n\r\n"
    body1, body2 = b"H" * 1000, b"B" * 500
    c, s = ISN_C + 1, ISN_S + 1
    pkts = [
        seg("c", "SYN", ISN_C),
        seg("s", "ACK,SYN", ISN_S, c),
        seg("c", "ACK", c, s),
        seg("c", "ACK,PSH", c, s, req, AppInfo("HTTP", "GET / HTTP/1.1")),
        seg("s", "ACK", s, c + len(req)),
        seg("s", "ACK,PSH", s, c + len(req), body1, AppInfo("HTTP", "HTTP/1.1 200 OK")),
        seg("s", "ACK,PSH", s + 1000, c + len(req), body2),
    ]
    c += len(req)
    s += 1500
    if fin_style == 4:
        pkts += [seg("c", "ACK,FIN", c, s), seg("s", "ACK", s, c + 1),
                 seg("s", "ACK,FIN", s, c + 1), seg("c", "ACK", c + 1, s + 1)]
    else:   # 3개로 끝나는 경우 (서버가 ACK와 FIN을 한 번에)
        pkts += [seg("c", "ACK,FIN", c, s), seg("s", "ACK,FIN", s, c + 1),
                 seg("c", "ACK", c + 1, s + 1)]
    return pkts


class TestTcpTracker(unittest.TestCase):
    def run_all(self, pkts):
        t = TcpTracker()
        done = [conn for p in pkts if (conn := t.add(p)) is not None]
        return t, done

    def test_full_connection(self):
        pkts = curl_session()
        t, done = self.run_all(pkts)
        self.assertEqual(len(done), 1)
        conn = done[0]
        self.assertEqual(conn.key, (*CLIENT, *SERVER))
        self.assertEqual(conn.state, "CLOSED")
        self.assertEqual(conn.app_name, "HTTP")
        self.assertEqual((conn.isn_client, conn.isn_server), (ISN_C, ISN_S))
        self.assertEqual([p.tcp["flags"] for p in conn.handshake], ["SYN", "ACK,SYN", "ACK"])
        self.assertEqual(conn.data_count, {"OUT": 1, "IN": 2})
        self.assertEqual(conn.data_bytes["IN"], 1500)
        self.assertEqual([p.tcp["flags"] for p in conn.teardown], ["ACK,FIN", "ACK", "ACK,FIN", "ACK"])
        self.assertEqual(conn.retransmissions, 0)
        self.assertEqual(t.remaining(), [])

    def test_relative_seq_ack_like_wireshark(self):
        pkts = curl_session()
        self.run_all(pkts)
        self.assertEqual((pkts[0].rel_seq, pkts[0].rel_ack), (0, None))
        self.assertEqual((pkts[1].rel_seq, pkts[1].rel_ack), (0, 1))
        self.assertEqual((pkts[2].rel_seq, pkts[2].rel_ack), (1, 1))
        self.assertEqual((pkts[6].rel_seq, pkts[6].rel_ack), (1001, 39))   # 서버 ISN wrap 넘어감
        self.assertEqual((pkts[-1].rel_seq, pkts[-1].rel_ack), (40, 1502))

    def test_three_segment_close(self):
        _t, done = self.run_all(curl_session(fin_style=3))
        self.assertEqual(done[0].state, "CLOSED")
        self.assertEqual(len(done[0].teardown), 3)

    def test_retransmission(self):
        pkts = curl_session()
        dup = seg("s", "ACK,PSH", ISN_S + 1, ISN_C + 1 + 39, b"H" * 1000)
        _t, done = self.run_all(pkts[:6] + [dup] + pkts[6:])
        self.assertEqual(done[0].retransmissions, 1)
        self.assertEqual(done[0].data_count["IN"], 2)

    def test_rst(self):
        pkts = curl_session()[:4] + [seg("s", "RST", ISN_S + 1)]
        t, done = self.run_all(pkts)
        self.assertEqual(done[0].state, "RESET")
        self.assertEqual(done[0].teardown[-1].tcp["flags"], "RST")
        self.assertEqual(t.remaining(), [])

    def test_opened_before_capture(self):
        pkts = curl_session()[3:7]                 # SYN 없이 데이터부터
        t, done = self.run_all(pkts)
        self.assertEqual(done, [])
        conn = t.remaining()[0]
        self.assertEqual(conn.key, (*CLIENT, *SERVER))
        self.assertEqual(conn.handshake, [])
        self.assertEqual(pkts[0].rel_seq, 0)

    def test_late_packet_after_close_is_not_new_connection(self):
        pkts = curl_session()
        late = seg("c", "ACK", ISN_C + 40, ISN_S + 1502)    # 마지막 ACK 재전송
        t, done = self.run_all(pkts + [late])
        self.assertEqual(len(done), 1)
        self.assertEqual(t.remaining(), [])
        self.assertEqual(late.rel_seq, 40)

    def test_syn_retransmission_kept_once(self):
        pkts = curl_session()
        pkts.insert(1, seg("c", "SYN", ISN_C))
        _t, done = self.run_all(pkts)
        self.assertEqual([p.tcp["flags"] for p in done[0].handshake], ["SYN", "ACK,SYN", "ACK"])

    def test_out_of_order_is_not_retransmission(self):
        pkts = curl_session()
        pkts[5], pkts[6] = pkts[6], pkts[5]            # 뒤 세그먼트가 먼저 도착
        _t, done = self.run_all(pkts)
        self.assertEqual(done[0].retransmissions, 0)
        self.assertEqual(done[0].data_count["IN"], 2)
        self.assertEqual(done[0].data_bytes["IN"], 1500)

    def test_keepalive_not_counted(self):
        pkts = curl_session()[:7]
        pkts.append(seg("c", "ACK", ISN_C + 38, ISN_S + 1501, b"\x00"))
        t, _ = self.run_all(pkts)
        conn = t.remaining()[0]
        self.assertEqual(conn.retransmissions, 0)
        self.assertEqual(conn.data_count["OUT"], 1)

    def test_syn_ack_first_keeps_wireshark_numbers(self):
        pkts = curl_session()[1:]                      # SYN은 못 보고 SYN,ACK부터
        _t, done = self.run_all(pkts)
        self.assertEqual((pkts[0].rel_seq, pkts[0].rel_ack), (0, 1))
        self.assertEqual((pkts[1].rel_seq, pkts[1].rel_ack), (1, 1))
        self.assertEqual(done[0].state, "CLOSED")
        self.assertEqual(done[0].key, (*CLIENT, *SERVER))

    def test_port_reuse_starts_new_connection(self):
        # 연결해제 마지막 ACK를 놓친 뒤 같은 포트로 새 연결 → 이전 연결은 끝내고 새 연결을 따로 추적
        old = curl_session(fin_style=3)[:-1]           # 마지막 ACK 없음
        isn = 12345
        new = [seg("c", "SYN", isn), seg("s", "ACK,SYN", 777, isn + 1),
               seg("c", "ACK", isn + 1, 778), seg("c", "ACK,PSH", isn + 1, 778, b"GET")]
        t, done = self.run_all(old + new)
        self.assertEqual(len(done), 1)                 # 새 SYN이 올 때 이전 연결이 나옴
        self.assertEqual(done[0].isn_client, ISN_C)
        self.assertEqual(done[0].state, "FIN_WAIT")
        self.assertEqual(done[0].data_count["OUT"], 1)
        conn = t.remaining()[0]
        self.assertEqual(conn.isn_client, isn)
        self.assertEqual([p.tcp["flags"] for p in conn.handshake], ["SYN", "ACK,SYN", "ACK"])
        self.assertEqual(conn.state, "ESTABLISHED")
        self.assertEqual((conn.data_count["OUT"], conn.data_bytes["OUT"]), (1, 3))
        self.assertEqual((new[3].rel_seq, new[3].rel_ack), (1, 1))

    def test_syn_after_syn_ack_first_is_same_connection(self):
        # SYN,ACK부터 잡힌 연결에 원래 SYN이 늦게 와도 새 연결이 아니다
        pkts = curl_session()
        pkts[0], pkts[1] = pkts[1], pkts[0]
        _t, done = self.run_all(pkts)
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0].state, "CLOSED")

    def test_non_tcp_ignored(self):
        pkt = seg("c", "SYN", 1)
        pkt.proto, pkt.tcp = "UDP", None
        t = TcpTracker()
        self.assertIsNone(t.add(pkt))
        self.assertEqual(t.remaining(), [])


if __name__ == "__main__":
    unittest.main()
