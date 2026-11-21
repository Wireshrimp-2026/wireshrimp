# =============================================================================
# 담당자  : A
# 맡은 기능: 캡처한 프레임을 pcap 파일로 저장 (Wireshark로 열 수 있는 형식)
#            - 전역 헤더 24B: magic 0xa1b2c3d4, 버전 2.4, snaplen 262144, linktype 1(Ethernet)
#            - 레코드 헤더 16B: ts_sec, ts_usec, incl_len, orig_len + 프레임 bytes
# 완료 기준: 캡처한 프레임이 pcap 형식으로 저장된다.
# =============================================================================
from __future__ import annotations

import struct

from .models import Captured

PCAP_MAGIC = 0xA1B2C3D4
VERSION_MAJOR, VERSION_MINOR = 2, 4
SNAPLEN = 262144             # capture.RECV_BUF와 같음
LINKTYPE_ETHERNET = 1


class PcapWriter:
    """Captured를 하나씩 pcap 파일에 쓴다.

    파일을 열 수 없으면(폴더 없음, 권한 없음) OSError를 그대로 올린다 → main에서 안내.
    """

    def __init__(self, path: str) -> None:
        """파일을 만들고 전역 헤더를 쓴다."""
        self.path = path
        self._f = open(path, "wb")
        # 엔디언은 기계 기준("="). magic 값을 보고 Wireshark가 알아서 맞춘다.
        self._f.write(struct.pack("=IHHiIII", PCAP_MAGIC, VERSION_MAJOR, VERSION_MINOR,
                                  0, 0, SNAPLEN, LINKTYPE_ETHERNET))
        self._f.flush()

    def write(self, captured: Captured) -> None:
        """레코드 헤더 + 프레임 1개를 쓴다. 중간에 멈춰도 그때까지는 남도록 매번 flush."""
        if self._f.closed:
            return
        sec = int(captured.ts)
        usec = int(round((captured.ts - sec) * 1_000_000))
        if usec >= 1_000_000:                # 반올림으로 1초가 되는 경우
            sec, usec = sec + 1, usec - 1_000_000
        frame = captured.frame[:SNAPLEN]
        self._f.write(struct.pack("=IIII", sec, usec, len(frame), len(captured.frame)))
        self._f.write(frame)
        self._f.flush()

    def close(self) -> None:
        if not self._f.closed:
            self._f.close()
