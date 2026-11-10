# =============================================================================
# 담당자  : C
# 맡은 기능: DNS 파싱 단위 테스트 (샘플: tests/samples/)
# 완료 기준: DNS 질의 도메인·응답 IP가 Wireshark와 일치한다.
# =============================================================================
import unittest

from src.decode.app_dns import parse_dns  # noqa: F401


class TestParseDns(unittest.TestCase):
    def test_todo(self):
        self.skipTest("TODO: 테스트 작성")


if __name__ == "__main__":
    unittest.main()
