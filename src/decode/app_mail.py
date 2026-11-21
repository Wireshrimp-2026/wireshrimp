# =============================================================================
# 담당자  : B
# 맡은 기능: e-mail 해석 (DESIGN 7.6) — 선택
#            - SMTP: EHLO/HELO, MAIL FROM, RCPT TO, DATA, QUIT, STARTTLS, AUTH / 3자리 응답 코드,
#              여러 줄 응답(250-), DATA 안 메일 헤더(From, To, Subject, Date)와 본문 길이
#            - POP3: USER, PASS, STAT, LIST, RETR, DELE, QUIT / +OK, -ERR, RETR 응답의 메일 헤더
#            - IMAP: 태그 + 명령(LOGIN, SELECT, FETCH, LOGOUT) / 태그 없는 응답(*), 태그 응답(OK/NO/BAD)
#            - 한 세그먼트의 여러 줄은 줄마다 해석
#            - STARTTLS 이후는 "TLS (암호화 시작)"으로 표시하고 해석 중단 (conn_key별로 이 파일 안에서 기억)
#            - 비밀번호(PASS, LOGIN, AUTH)는 **** 로 가림
# 완료 기준: SMTP·POP3·IMAP 명령·응답이 AppInfo로 나오고 비밀번호가 가려진다.
# =============================================================================
from __future__ import annotations

from ..models import AppInfo, ConnKey


def parse_smtp(conn_key: ConnKey, data: bytes, from_client: bool) -> AppInfo:
    """SMTP 세그먼트 → AppInfo(name="SMTP")."""
    raise NotImplementedError


def parse_pop3(conn_key: ConnKey, data: bytes, from_client: bool) -> AppInfo:
    """POP3 세그먼트 → AppInfo(name="POP3")."""
    raise NotImplementedError


def parse_imap(conn_key: ConnKey, data: bytes, from_client: bool) -> AppInfo:
    """IMAP 세그먼트 → AppInfo(name="IMAP")."""
    raise NotImplementedError
