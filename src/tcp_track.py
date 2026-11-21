# =============================================================================
# 담당자  : A
# 맡은 기능: F3 TCP 연결 추적 (DESIGN 7.3)
#            - 연결설정: SYN → SYN,ACK → ACK. 양쪽 ISN 저장
#            - 데이터 전송: payload가 있는 세그먼트를 방향별로 개수·바이트 누적, 재전송(같은 Seq) 따로 셈
#            - 연결해제: FIN 교환 + 마지막 ACK (FIN,ACK가 겹쳐 3개로 끝나도 정상) / RST는 비정상 종료
#            - 상대 Seq/Ack: pkt.rel_seq = seq - ISN, pkt.rel_ack = ack - 상대 ISN
#            - 연결 이름: 처음 판별된 pkt.app.name
# 완료 기준: curl 1회가 연결 요약(Connection) 1개로 나온다 (연결설정 3개, 데이터, 연결해제).
#            상대 Seq/Ack가 PacketInfo에 채워진다.
# =============================================================================
from __future__ import annotations

from typing import Optional

from .models import Connection, PacketInfo


class TcpTracker:
    """PacketInfo를 하나씩 받아 TCP 연결 상태를 갱신한다."""

    def add(self, pkt: PacketInfo) -> Optional[Connection]:
        """TCP 패킷이면 상대 Seq/Ack를 채우고 연결 상태를 갱신.

        연결이 이 패킷으로 끝났으면(마지막 ACK 또는 RST) 그 Connection을, 아니면 None.
        TCP가 아니면 아무것도 하지 않고 None.
        """
        raise NotImplementedError

    def remaining(self) -> list[Connection]:
        """프로그램 종료 시 아직 끝나지 않은 연결 목록 (시작 순)."""
        raise NotImplementedError
