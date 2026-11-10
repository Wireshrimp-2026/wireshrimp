# =============================================================================
# 담당자  : C
# 맡은 기능: F2 계층별 해석 — HTTP 파싱
#            - 요청: Method, URL, Host / 응답: 상태 코드, Reason, Content-Length
#            - 요청/응답의 첫 줄과 헤더가 있는 패킷에서만 채움 (본문 패킷은 None)
#            - 데이터가 깨졌으면 ValueError
# 완료 기준: DNS 질의 도메인·응답 IP, HTTP 메서드·상태 코드가 Wireshark와 일치한다.
#            dns_ms, tcp_connect_ms, http_first_byte_ms, total_ms가 계산된다.
#            조건별 평균·최대·표준편차 그래프와 단계 누적 막대 그래프가 나온다.
# =============================================================================
from __future__ import annotations

from typing import Optional

from ..models import HttpInfo


def parse_http(data: bytes) -> Optional[HttpInfo]:
    """TCP 페이로드 → HttpInfo, 첫 줄이 HTTP 요청/응답이 아니면 None."""
    raise NotImplementedError
