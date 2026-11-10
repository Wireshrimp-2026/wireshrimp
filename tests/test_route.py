# =============================================================================
# 담당자  : D
# 맡은 기능: traceroute 경로 추적·홉별 지연 단위 테스트 (샘플: tests/samples/)
# 완료 기준: ICMP Type·Code·원본 목적지 IP·포트가 Wireshark와 일치한다. traceroute 프로브와 ICMP 응답이 짝지어져 홉별 지연이 계산된다. 설계안 출력 예시 모양의 타임라인이 찍히고 CSV가 2.6 형식으로 쌓인다.
# =============================================================================
import unittest

from src.route import RouteTracker, hop_delays  # noqa: F401


class TestRouteTracker(unittest.TestCase):
    def test_todo(self):
        self.skipTest("TODO: 테스트 작성")


class TestHopDelays(unittest.TestCase):
    def test_todo(self):
        self.skipTest("TODO: 테스트 작성")


if __name__ == "__main__":
    unittest.main()
