# =============================================================================
# 담당자  : B
# 맡은 기능: TLS 레코드 헤더 표시 (DESIGN 7.9) — 내용은 암호화되어 해석하지 않음
#            - Content Type(20 ChangeCipherSpec, 21 Alert, 22 Handshake, 23 Application Data),
#              Version, Length
# 완료 기준: 443·465·993·995 포트의 세그먼트가 "TLS record type=…" AppInfo로 나온다.
# =============================================================================
from __future__ import annotations

from typing import Optional

from ..models import AppInfo


def parse_tls(data: bytes) -> Optional[AppInfo]:
    """TCP 페이로드 → AppInfo(name="TLS"), TLS 레코드가 아니면 None."""
    raise NotImplementedError
