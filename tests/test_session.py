# =============================================================================
# 담당자  : B
# 맡은 기능: F3 접속 단위로 묶기 단위 테스트 (샘플: tests/samples/)
# 완료 기준: Seq/Ack/Flags, UDP 포트·Length가 Wireshark와 일치한다. 접속 1회가 Session 1개로 묶이고, SYN·SYN/ACK·ACK·HTTP 요청·응답·FIN이 모두 붙는다.
# =============================================================================
import unittest

from src.session import SessionBuilder  # noqa: F401


class TestSessionBuilder(unittest.TestCase):
    def test_todo(self):
        self.skipTest("TODO: 테스트 작성")


if __name__ == "__main__":
    unittest.main()
