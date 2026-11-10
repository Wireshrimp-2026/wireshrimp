# =============================================================================
# 담당자  : C
# 맡은 기능: HTTP 파싱 단위 테스트 (샘플: tests/samples/)
# 완료 기준: HTTP 메서드·상태 코드가 Wireshark와 일치한다.
# =============================================================================
import unittest

from src.decode.app_http import parse_http  # noqa: F401


class TestParseHttp(unittest.TestCase):
    def test_todo(self):
        self.skipTest("TODO: 테스트 작성")


if __name__ == "__main__":
    unittest.main()
