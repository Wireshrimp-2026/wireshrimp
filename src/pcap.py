# =============================================================================
# 담당자  : A
# 맡은 기능: 캡처한 프레임을 pcap 파일로 저장 (Wireshark로 열 수 있는 형식)
#            - 전역 헤더 24B: magic 0xa1b2c3d4, 버전 2.4, snaplen 262144, linktype 1(Ethernet)
#            - 레코드 헤더 16B: ts_sec, ts_usec, incl_len, orig_len + 프레임 bytes
# 완료 기준: 캡처한 프레임이 pcap 형식으로 저장된다.
# =============================================================================
from __future__ import annotations

from .models import Captured


class PcapWriter:
    """Captured를 하나씩 pcap 파일에 쓴다."""

    def __init__(self, path: str) -> None:
        """파일을 만들고 전역 헤더를 쓴다."""
        raise NotImplementedError

    def write(self, captured: Captured) -> None:
        """레코드 헤더 + 프레임 1개를 쓴다."""
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
