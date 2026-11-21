# =============================================================================
# 맡은 기능: 평문 SMTP·POP3·IMAP 테스트 서버 (DESIGN 8장) — 분석기 본체가 아닌 트래픽 발생용
#            - socket + threading, 미리 넣어 둔 메일 1통, 계정 user / pass
#            - 분석기를 돌리는 PC가 아닌 다른 PC에서 실행 (같은 PC면 lo로만 오가서 안 잡힘)
#            - 기본 포트 25/110/143 (sudo 필요). 권한이 없으면 2525/2110/2143
#              → 분석기에 --port smtp=2525,pop3=2110,imap=2143
#            python3 tools/mail_server.py [--smtp 2525] [--pop3 2110] [--imap 2143]
# =============================================================================
from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError


if __name__ == "__main__":
    sys.exit(main())
