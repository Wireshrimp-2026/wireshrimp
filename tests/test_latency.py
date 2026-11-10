# =============================================================================
# 담당자  : C
# 맡은 기능: F4 지연 측정 단위 테스트 (샘플: tests/samples/)
# 완료 기준: dns_ms, tcp_connect_ms, http_first_byte_ms, total_ms, 홉별 지연이 계산된다.
# =============================================================================
import unittest

from src.latency import measure  # noqa: F401


class TestMeasure(unittest.TestCase):
    def test_todo(self):
        self.skipTest("TODO: 테스트 작성")


if __name__ == "__main__":
    unittest.main()
