# =============================================================================
# 담당자  : A
# 맡은 기능: Ethernet·IP 파싱, decode() 단위 테스트 (샘플: tests/samples/)
# 완료 기준: IP·TTL이 Wireshark와 일치한다.
# =============================================================================
import unittest

from src.decode.link_ip import parse_ethernet, parse_ip  # noqa: F401


class TestParseEthernet(unittest.TestCase):
    def test_todo(self):
        self.skipTest("TODO: 테스트 작성")


class TestParseIp(unittest.TestCase):
    def test_todo(self):
        self.skipTest("TODO: 테스트 작성")


if __name__ == "__main__":
    unittest.main()
