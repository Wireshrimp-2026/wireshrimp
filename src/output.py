# =============================================================================
# 담당자  : D
# 맡은 기능: F5 출력·저장
#            - 실시간 한 줄 출력: "[DNS] OUT 10.0.2.15 -> 8.8.8.8 query A neverssl.com id=0x1a2b"
#            - 접속 1회 요약 타임라인 ([DNS] → [ROUTE] → [TCP] → [HTTP] → [TCP] 종료)
#            - CSV 기록 (models.CSV_COLUMNS 순서, None은 빈 칸, hop_delays는 "2.1;*;14.8")
# 완료 기준: ICMP Type·Code·원본 목적지 IP·포트가 Wireshark와 일치한다. traceroute 프로브와
#            ICMP 응답이 짝지어져 홉별 지연이 계산된다. 설계안 출력 예시 모양의 타임라인이
#            찍히고 CSV가 2.6 형식으로 쌓인다.
# =============================================================================
from __future__ import annotations

from .models import LatencyResult, PacketInfo, Session


def print_packet(pkt: PacketInfo) -> None:
    """패킷 1건을 실시간 한 줄로 출력 ([DNS] OUT ... 형식)."""
    raise NotImplementedError


def print_timeline(session: Session, result: LatencyResult) -> None:
    """접속 1회의 요약 타임라인을 출력."""
    raise NotImplementedError


class CsvWriter:
    """LatencyResult를 CSV 한 줄씩 쌓는다."""

    def __init__(self, path: str, dns_server: str, network: str) -> None:
        self.path = path
        self.dns_server = dns_server   # 실험 조건 라벨 (예: google)
        self.network = network         # 실험 조건 라벨 (예: school-wifi)

    def write(self, result: LatencyResult) -> None:
        """LatencyResult → CSV 한 줄 추가 (파일이 없으면 헤더부터)."""
        raise NotImplementedError
