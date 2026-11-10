# =============================================================================
# 담당자  : C
# 맡은 기능: F4 단계별 지연 측정 (짝 패킷의 시간 차, ms)
#            - DNS 응답 : 질의(OUT) → 응답(IN)            짝: Transaction ID
#            - TCP 연결 : SYN(OUT) → SYN+ACK(IN)          짝: IP·포트 4개 묶음
#            - HTTP 응답: GET(OUT) → 데이터 있는 첫 응답(IN) 짝: 같은 TCP 연결
#            - 전체     : DNS 질의 → 마지막 FIN/ACK        짝: 같은 접속
#            - 측정할 수 없는 값은 0이 아니라 None
#            (홉별 지연 hops는 route.hop_delays() — D, main.py가 채움)
# 완료 기준: DNS 질의 도메인·응답 IP, HTTP 메서드·상태 코드가 Wireshark와 일치한다.
#            dns_ms, tcp_connect_ms, http_first_byte_ms, total_ms가 계산된다.
#            조건별 평균·최대·표준편차 그래프와 단계 누적 막대 그래프가 나온다.
# =============================================================================
from __future__ import annotations

from .models import LatencyResult, Session


def measure(session: Session) -> LatencyResult:
    """Session 1개 → 단계별 지연 LatencyResult (hops는 빈 목록으로 둠)."""
    raise NotImplementedError
