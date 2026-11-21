# =============================================================================
# TCP·UDP 헤더 파싱 단위 테스트
# =============================================================================
import socket
import struct
import unittest

from src.decode.transport import flags_to_str, parse_tcp, parse_tcp_options, parse_udp

# 리눅스 curl SYN의 실제 옵션 모양: MSS 1460, SACK_PERM, TS, NOP, WS 7
LINUX_SYN_OPTS = (bytes.fromhex("020405b4" "0402" "080a") + struct.pack("!II", 123456, 0)
                  + bytes.fromhex("01" "030307"))


def tcp(sport=51234, dport=80, seq=1000, ack=0, flags=0x02, window=64240,
        options=b"", payload=b"", ns=False, urgent=0):
    off = (5 + len(options) // 4) << 4 | (1 if ns else 0)
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags, window, 0xBEEF,
                       urgent) + options + payload


def ones_sum(data: bytes) -> int:
    """테스트용 체크섬 계산 (본 코드와 다른 방법: 2바이트씩 직접 더함)."""
    if len(data) % 2:
        data += b"\0"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def udp(src="10.0.2.15", dst="8.8.8.8", sport=40000, dport=53, payload=b"DNSQUERY",
        checksum=None):
    length = 8 + len(payload)
    if checksum is None:
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, length)
        checksum = ones_sum(pseudo + struct.pack("!HHHH", sport, dport, length, 0) + payload) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, checksum) + payload


class TestParseTcp(unittest.TestCase):
    def test_syn_with_options(self):
        info, payload = parse_tcp(tcp(options=LINUX_SYN_OPTS))
        self.assertEqual((info["src_port"], info["dst_port"]), (51234, 80))
        self.assertEqual((info["seq"], info["ack"]), (1000, 0))
        self.assertEqual(info["header_len"], 40)
        self.assertEqual(info["flags"], "SYN")
        self.assertEqual(info["window"], 64240)
        self.assertEqual(info["checksum"], 0xBEEF)
        self.assertEqual(info["options"],
                         ["MSS=1460", "SACK_PERM", "TS val=123456 ecr=0", "NOP", "WS=7"])
        self.assertEqual(payload, b"")

    def test_payload_and_flag_order(self):
        info, payload = parse_tcp(tcp(flags=0x18, payload=b"GET / HTTP/1.1\r\n"))
        self.assertEqual(info["flags"], "ACK,PSH")
        self.assertEqual(payload, b"GET / HTTP/1.1\r\n")
        self.assertEqual(flags_to_str(0x12), "ACK,SYN")
        self.assertEqual(flags_to_str(0x11), "ACK,FIN")
        self.assertEqual(flags_to_str(0xFF), "CWR,ECE,URG,ACK,PSH,RST,SYN,FIN")
        self.assertEqual(flags_to_str(0), "")

    def test_ns_bit_and_urgent(self):
        info, _ = parse_tcp(tcp(flags=0x30, ns=True, urgent=7))
        self.assertEqual(info["flag_bits"], 0x130)
        self.assertEqual(info["flags"], "URG,ACK")
        self.assertEqual(info["urgent"], 7)

    def test_sack_and_unknown_options(self):
        sack = bytes([5, 10]) + struct.pack("!II", 100, 200) + b"\x01\x01"
        self.assertEqual(parse_tcp_options(sack), ["SACK=100-200", "NOP", "NOP"])
        self.assertEqual(parse_tcp_options(bytes([30, 4, 0, 0])), ["OPT30 len=4"])
        self.assertEqual(parse_tcp_options(b"\x01\x00\x00\x00"), ["NOP", "EOL"])
        self.assertEqual(parse_tcp_options(bytes([5, 2])), ["OPT5 len=2"])   # 블록 없는 SACK

    def test_broken_option_does_not_fail_header(self):
        self.assertEqual(parse_tcp_options(bytes([2, 9, 5, 180])), ["BAD_OPTION"])
        self.assertEqual(parse_tcp_options(bytes([1, 2])), ["NOP", "BAD_OPTION"])
        info, _ = parse_tcp(tcp(options=bytes([2, 0, 0, 0])))
        self.assertEqual(info["options"], ["BAD_OPTION"])

    def test_errors(self):
        with self.assertRaises(ValueError):
            parse_tcp(b"\x00" * 19)
        bad_off = bytearray(tcp())
        bad_off[12] = 4 << 4
        with self.assertRaises(ValueError):
            parse_tcp(bytes(bad_off))                       # data offset < 20
        with self.assertRaises(ValueError):
            parse_tcp(tcp(options=LINUX_SYN_OPTS)[:30])     # 옵션이 잘림


class TestParseUdp(unittest.TestCase):
    def test_fields_and_valid_checksum(self):
        info, payload = parse_udp(udp(), "10.0.2.15", "8.8.8.8")
        self.assertEqual((info["src_port"], info["dst_port"]), (40000, 53))
        self.assertEqual(info["length"], 16)
        self.assertTrue(info["checksum_ok"])
        self.assertEqual(payload, b"DNSQUERY")

    def test_odd_length_payload(self):
        info, payload = parse_udp(udp(payload=b"ABC"), "10.0.2.15", "8.8.8.8")
        self.assertTrue(info["checksum_ok"])
        self.assertEqual(payload, b"ABC")

    def test_bad_checksum(self):
        data = bytearray(udp())
        data[-1] ^= 0xFF                                     # 데이터 1바이트 변조
        info, _ = parse_udp(bytes(data), "10.0.2.15", "8.8.8.8")
        self.assertFalse(info["checksum_ok"])
        # 의사 헤더 주소가 다르면 틀려야 한다
        info, _ = parse_udp(udp(), "10.0.2.15", "1.1.1.1")
        self.assertFalse(info["checksum_ok"])

    def test_offload_partial_checksum(self):
        # 실제 veth 캡처 값: 10.9.0.2:53 -> 10.9.0.1, UDP length 75, 체크섬 칸 = 의사 헤더 합 0x1471
        data = udp(src="10.9.0.2", dst="10.9.0.1", sport=53, dport=57483, payload=b"x" * 67,
                   checksum=0x1471)
        info, _ = parse_udp(data, "10.9.0.2", "10.9.0.1")
        self.assertFalse(info["checksum_ok"])
        self.assertTrue(info["checksum_partial"])
        info, _ = parse_udp(udp(), "10.0.2.15", "8.8.8.8")
        self.assertFalse(info["checksum_partial"])          # 맞는 체크섬은 partial 아님
        bad = bytearray(udp()); bad[-1] ^= 0xFF
        info, _ = parse_udp(bytes(bad), "10.0.2.15", "8.8.8.8")
        self.assertFalse(info["checksum_partial"])          # 진짜 손상은 partial 아님

    def test_checksum_unused_or_truncated(self):
        info, _ = parse_udp(udp(checksum=0), "10.0.2.15", "8.8.8.8")
        self.assertIsNone(info["checksum_ok"])               # 0 = 체크섬 안 씀
        info, payload = parse_udp(udp()[:12], "10.0.2.15", "8.8.8.8")
        self.assertIsNone(info["checksum_ok"])               # 잘려서 검증 불가
        self.assertEqual(payload, b"DNSQ")

    def test_trailing_bytes_ignored(self):
        info, payload = parse_udp(udp() + b"\x00\x00", "10.0.2.15", "8.8.8.8")
        self.assertTrue(info["checksum_ok"])
        self.assertEqual(payload, b"DNSQUERY")

    def test_errors(self):
        with self.assertRaises(ValueError):
            parse_udp(b"\x00" * 7, "10.0.2.15", "8.8.8.8")
        with self.assertRaises(ValueError):
            parse_udp(struct.pack("!HHHH", 1, 2, 7, 0), "10.0.2.15", "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
