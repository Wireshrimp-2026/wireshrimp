# =============================================================================
# 담당자  : B
# 맡은 기능: TCP·UDP·ICMP 파싱 단위 테스트 (샘플: tests/samples/)
# 완료 기준: Seq/Ack/Flags가 Wireshark와 일치한다. 접속 1회가 Session 1개로 묶이고 SYN·SYN/ACK·ACK·FIN이 모두 붙는다. traceroute 프로브와 ICMP 응답이 짝지어진다.
# =============================================================================
import unittest

from src.decode.transport import parse_icmp, parse_tcp, parse_udp  # noqa: F401


class TestParseTcp(unittest.TestCase):
    def test_todo(self):
        self.skipTest("TODO: 테스트 작성")


class TestParseUdp(unittest.TestCase):
    def test_todo(self):
        self.skipTest("TODO: 테스트 작성")


class TestParseIcmp(unittest.TestCase):
    def test_todo(self):
        self.skipTest("TODO: 테스트 작성")


if __name__ == "__main__":
    unittest.main()
