# =============================================================================
# 담당자  : B
# 맡은 기능: HTTP 해석 (DESIGN 7.5) — 필수
#            - 요청: Method, Request-URI, Version, 헤더 전체
#            - 응답: Version, Status Code, Reason Phrase, 헤더 전체
#            - 헤더 끝(\r\n\r\n) 뒤 본문은 "body: N bytes"만
#            - 첫 줄이 HTTP가 아니면 parse_http()는 None (함수 약속, DESIGN 6장)
#              → HTTP 포트의 세그먼트면 parse_app()이 http_continuation()으로 "continuation N bytes"
#            - 헤더가 다음 세그먼트로 이어지면 있는 만큼만 해석하고 그렇다고 표시
#            - 화면에 찍는 값은 제어 문자를 \xNN으로 바꾸고 너무 길면 자른다 (fields에는 원래 값)
# 완료 기준: HTTP 요청줄·상태줄·헤더가 AppInfo로 나온다.
# =============================================================================
from __future__ import annotations

import re
from typing import Optional

from ..models import AppInfo

# 요청줄: METHOD SP Request-URI SP HTTP-Version   예) GET / HTTP/1.1
REQUEST_LINE = re.compile(r"([A-Z]+) (\S+) (HTTP/\d(?:\.\d)?)")
# 상태줄: HTTP-Version SP Status-Code SP Reason   예) HTTP/1.1 200 OK  (Reason은 비어도 됨)
STATUS_LINE = re.compile(r"(HTTP/\d(?:\.\d)?) (\d{3})(?: (.*))?")

MAX_SHOW = 200       # 화면에 보여 줄 헤더 한 줄 최대 글자 수


def parse_http(data: bytes) -> Optional[AppInfo]:
    """TCP 페이로드 → AppInfo(name="HTTP"), 첫 줄이 HTTP 요청줄·상태줄이 아니면 None.

    fields 키: is_request, method, uri, version, status_code, reason, headers(dict), body_len,
              headers_complete (헤더 끝 빈 줄까지 이 세그먼트에 있으면 True)
    """
    if not data:
        return None
    head, body, complete = _split_head(data)
    text = head.decode("utf-8", errors="replace")
    first, *header_lines = re.split(r"\r?\n", text)

    request = REQUEST_LINE.fullmatch(first)
    status = None if request else STATUS_LINE.fullmatch(first)
    if request is None and status is None:
        return None

    fields: dict = {"is_request": request is not None, "method": None, "uri": None,
                    "version": None, "status_code": None, "reason": None}
    if request:
        fields["method"], fields["uri"], fields["version"] = request.groups()
    else:
        fields["version"], code, reason = status.groups()
        fields["status_code"] = int(code)
        fields["reason"] = reason or ""

    headers, lines = _parse_headers(header_lines)
    if complete:
        if body:
            lines.append(f"body: {len(body)} bytes")
    else:
        lines.append("(헤더가 다음 세그먼트로 이어짐)")
    fields.update(headers=headers, body_len=len(body), headers_complete=complete)
    return AppInfo(name="HTTP", summary=_show(first), lines=lines, fields=fields)


def http_continuation(data: bytes) -> AppInfo:
    """첫 줄이 HTTP가 아닌 HTTP 연결 세그먼트(응답 본문이 이어지는 중) → "continuation N bytes"."""
    return AppInfo(name="HTTP", summary=f"continuation {len(data)} bytes",
                   fields={"is_request": None, "continuation": True, "body_len": len(data)})


def _split_head(data: bytes) -> tuple[bytes, bytes, bool]:
    """(헤더 부분, 본문, 헤더 끝 빈 줄을 찾았는지). 줄 끝이 \\n뿐인 경우도 받아 준다."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        end = data.find(sep)
        if end != -1:
            return data[:end], data[end + len(sep):], True
    return data, b"", False


def _parse_headers(raw_lines: list[str]) -> tuple[dict, list[str]]:
    """헤더 줄 → ({이름: 값}, 화면에 찍을 줄 목록).

    같은 이름이 여러 번 오면(Set-Cookie 등) 값은 ", "로 이어 붙이고 줄은 각각 남긴다.
    공백으로 시작하는 줄은 앞 헤더 값이 이어지는 것(obs-fold)으로 본다.
    """
    headers: dict = {}
    lines: list[str] = []
    last: Optional[str] = None
    for raw in raw_lines:
        if not raw:
            continue
        if raw[0] in " \t" and last is not None:          # 앞 헤더가 다음 줄로 접혀 이어짐
            headers[last] += " " + raw.strip()
            lines[-1] += " " + _show(raw.strip())
            continue
        name, colon, value = raw.partition(":")
        if colon and name and name == name.strip():
            name, value = name, value.strip()
            headers[name] = f"{headers[name]}, {value}" if name in headers else value
            last = name
            lines.append(_show(f"{name}: {value}"))
        else:                                             # "이름: 값" 모양이 아닌 줄도 보이게 둔다
            last = None
            lines.append(_show(raw))
    return headers, lines


def _show(text: str) -> str:
    """화면용: 제어 문자(터미널 색·커서를 바꿀 수 있음)는 \\xNN으로, 너무 길면 … 로 자른다."""
    safe = "".join(ch if ch == "\t" or (ord(ch) >= 0x20 and ord(ch) != 0x7F) else f"\\x{ord(ch):02x}"
                   for ch in text)
    return safe if len(safe) <= MAX_SHOW else safe[:MAX_SHOW] + "…"
