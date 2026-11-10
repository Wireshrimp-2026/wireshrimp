# =============================================================================
# 담당자  : C
# 맡은 기능: F2 계층별 해석 — DNS 파싱
#            - Transaction ID, Flags(QR 비트), 질의 도메인·Type, 응답 IP·TTL (A 레코드)
#            - 이름 압축 포인터 처리
#            - 데이터가 짧거나 깨졌으면 ValueError
# 완료 기준: DNS 질의 도메인·응답 IP, HTTP 메서드·상태 코드가 Wireshark와 일치한다.
#            dns_ms, tcp_connect_ms, http_first_byte_ms, total_ms가 계산된다.
#            조건별 평균·최대·표준편차 그래프와 단계 누적 막대 그래프가 나온다.
# =============================================================================
from __future__ import annotations

from ..models import DnsInfo


def parse_dns(data: bytes) -> DnsInfo:
    """UDP 페이로드(DNS 메시지) → DnsInfo."""
    raise NotImplementedError
