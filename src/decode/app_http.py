# =============================================================================
# 담당자  : B
# 맡은 기능: HTTP 해석 (DESIGN 7.5) — 필수
#            - 요청: Method, Request-URI, Version, 헤더 전체
#            - 응답: Version, Status Code, Reason Phrase, 헤더 전체
#            - 헤더 끝(\r\n\r\n) 뒤 본문은 "body: N bytes"만
#            - 첫 줄이 HTTP가 아닌 세그먼트(본문 이어짐)는 "continuation N bytes"
# 완료 기준: HTTP 요청줄·상태줄·헤더가 AppInfo로 나온다.
# =============================================================================
from __future__ import annotations

from typing import Optional

from ..models import AppInfo


def parse_http(data: bytes) -> Optional[AppInfo]:
    """TCP 페이로드 → AppInfo(name="HTTP").

    fields 키: is_request, method, uri, version, status_code, reason, headers(dict), body_len
    """
    raise NotImplementedError
