# =============================================================================
# 맡은 기능: 평문 SMTP·POP3·IMAP 테스트 서버 (DESIGN 8장) — 분석기 본체가 아닌 트래픽 발생용
#            - socket + threading, 미리 넣어 둔 메일 1통, 계정 user / pass
#            - 분석기를 돌리는 PC가 아닌 다른 PC에서 실행 (같은 PC면 lo로만 오가서 안 잡힘)
#            - 기본 포트 25/110/143 (리눅스는 sudo 필요). 권한이 없으면 2525/2110/2143
#              → 분석기에 --port smtp=2525,pop3=2110,imap=2143
#            python3 tools/mail_server.py [--smtp 2525] [--pop3 2110] [--imap 2143] [--bind IP]
#            - curl·smtplib·poplib·imaplib가 쓰는 명령을 받는다
#              SMTP: EHLO HELO MAIL RCPT DATA RSET NOOP HELP VRFY AUTH(PLAIN·LOGIN) QUIT
#              POP3: CAPA USER PASS STAT LIST UIDL RETR TOP DELE RSET NOOP QUIT
#              IMAP: CAPABILITY NOOP LOGIN SELECT EXAMINE LIST LSUB FETCH SEARCH (UID FETCH·SEARCH)
#                    APPEND CLOSE UNSELECT EXPUNGE LOGOUT
#            - 명령이 분석기에 평문으로 보이도록 STARTTLS·STLS는 거절하고, POP3·IMAP은 SASL·APOP을
#              알리지 않는다 → curl -u가 POP3는 USER/PASS, IMAP은 LOGIN을 쓴다
#              (SMTP는 AUTH PLAIN·LOGIN을 알림. curl은 -u를 줄 때만 AUTH를 보낸다)
#            - 여러 줄 응답도 한 번에 보낸다 → 보통 세그먼트 하나에 담긴다
#            - SMTP로 받은 메일과 IMAP APPEND는 메일함 뒤에 붙어 POP3·IMAP으로 다시 읽을 수 있다
#              (서버를 끄면 사라짐). POP3 DELE는 그 세션에서만 지운 것으로 보이고 실제로는 남긴다
#              → 시연을 몇 번 해도 1번 메일이 그대로
#            - Ctrl+C(SIGINT)·kill(SIGTERM)이면 열린 연결을 닫고 끝낸다. bash에서 '&'로 띄우면 SIGINT가
#              무시 상태로 물려받아지므로 되살린다 (src/main.py와 같은 처리)
# 완료 기준: DESIGN 8장의 curl smtp:// · pop3:// · imap:// 명령이 성공한다.
# =============================================================================
from __future__ import annotations

import argparse
import base64
import binascii
import errno
import re
import select
import selectors
import signal
import socket
import sys
import threading
import time
from typing import Callable, Optional

USER, PASSWORD = "user", "pass"
HOSTNAME = "mail.test.local"
DEFAULT_PORTS = {"smtp": 25, "pop3": 110, "imap": 143}
NO_SUDO_PORTS = {"smtp": 2525, "pop3": 2110, "imap": 2143}

MAX_LINE = 8192                   # 명령 한 줄 최대 바이트
MAX_MESSAGE = 10 * 1024 * 1024    # 메일 한 통 최대 크기 (EHLO SIZE로 알림)
MAX_MAILS = 100                   # 메일함 최대 통수
IDLE_TIMEOUT = 600                # 이 시간(초) 동안 아무것도 오지 않으면 연결을 끊는다

# 미리 넣어 둔 메일 1통 (POP3 RETR 1, IMAP UID FETCH 1)
FIRST_MAIL = (b"From: wireshrimp <test@test.local>\r\n"
              b"To: user <user@test.local>\r\n"
              b"Subject: wireshrimp test mail\r\n"
              b"Date: Sun, 22 Nov 2026 12:00:00 +0900\r\n"
              b"Message-ID: <1@test.local>\r\n"
              b"\r\n"
              b"Hello from the wireshrimp mail test server.\r\n"
              b"POP3 RETR 1 and IMAP UID FETCH 1 read this message.\r\n")

Log = Callable[[str], None]


class LineTooLong(Exception):
    """명령 한 줄이 MAX_LINE을 넘음."""


class Mailbox:
    """모든 연결이 같이 쓰는 메일함. 지우지 않으므로 메일 번호 = IMAP UID (1부터)."""

    def __init__(self, first: bytes = FIRST_MAIL) -> None:
        self._lock = threading.Lock()
        self._mails = [first]
        self.uidvalidity = int(time.time())    # 서버를 다시 켜면 UID가 1부터 다시 → 값도 바뀐다

    def add(self, message: bytes) -> Optional[int]:
        """메일을 뒤에 붙이고 번호를 돌려준다. 꽉 찼으면 None. 줄 끝은 CRLF로 맞춘다 (크기 계산용)."""
        message = re.sub(rb"\r?\n", b"\r\n", message)
        with self._lock:
            if len(self._mails) >= MAX_MAILS:
                return None
            self._mails.append(message)
            return len(self._mails)

    def snapshot(self) -> list[bytes]:
        with self._lock:
            return list(self._mails)


class Reader:
    """소켓에서 줄·바이트를 읽는다. 기다리는 동안 서버의 종료 신호(stop 소켓)도 같이 본다.

    makefile()로 막혀 읽는 스레드는 윈도우에서 다른 스레드의 shutdown()으로 깨어나지 않는다
    → stop()이 연결 스레드를 바로 끝낼 수 있게 select()로 둘 다 기다린다.
    """

    def __init__(self, sock: socket.socket, stop: socket.socket) -> None:
        self.sock, self.stop = sock, stop
        self.buf = bytearray()

    def readline(self, limit: int) -> bytes:
        """줄 끝(LF)까지, 최대 limit 바이트. 끊기면 그때까지 받은 것 (없으면 b"")."""
        searched = 0
        while True:
            end = self.buf.find(b"\n", searched, limit)
            if end != -1:
                return self._take(end + 1)
            searched = len(self.buf)
            if searched >= limit or not self._receive():
                return self._take(min(searched, limit))

    def read(self, size: int) -> bytes:
        """size 바이트 (끊기면 그보다 적게)."""
        while len(self.buf) < size and self._receive():
            pass
        return self._take(min(size, len(self.buf)))

    def _receive(self) -> bool:
        """더 받는다. 끊김·서버 종료, 또는 IDLE_TIMEOUT 동안 아무것도 안 오면 False."""
        ready, _, _ = select.select([self.sock, self.stop], [], [], IDLE_TIMEOUT)
        if self.sock not in ready or self.stop in ready:
            return False
        data = self.sock.recv(65536)
        self.buf += data
        return bool(data)

    def _take(self, n: int) -> bytes:
        data = bytes(self.buf[:n])
        del self.buf[:n]
        return data


# -----------------------------------------------------------------------------
# 연결 하나 (프로토콜마다 greet()·handle()을 만든다)
# -----------------------------------------------------------------------------
class Session:
    name = ""
    too_long = ""                  # 명령 줄이 너무 길 때 보내고 끊을 응답

    def __init__(self, sock: socket.socket, addr, mailbox: Mailbox, log: Log,
                 stop: socket.socket) -> None:
        self.sock = sock
        self.reader = Reader(sock, stop)
        self.peer = f"{addr[0]}:{addr[1]}"
        self.mailbox = mailbox
        self._log = log
        self.done = False          # QUIT·LOGOUT을 받으면 True → 연결을 닫는다

    def log(self, text: str) -> None:
        self._log(f"[{self.name}] {self.peer} {text}")

    def send(self, *lines: str) -> None:
        """응답 줄들을 한 번에 보낸다 (여러 줄 응답도 세그먼트 하나에 담기게)."""
        self.sock.sendall("".join(line + "\r\n" for line in lines).encode())

    def readline(self) -> Optional[bytes]:
        """줄 끝(CRLF 또는 LF)을 뗀 한 줄. 연결이 끊기면 None, 너무 길면 LineTooLong."""
        line = self.reader.readline(MAX_LINE + 1)
        if not line.endswith(b"\n"):
            if len(line) > MAX_LINE:
                raise LineTooLong
            return None            # 연결 끊김 (줄 중간에서 끊긴 것도)
        return line[:-2] if line.endswith(b"\r\n") else line[:-1]

    def next_command(self):
        line = self.readline()
        return None if line is None else line.decode("utf-8", "replace")

    def run(self) -> None:
        self.log("연결")
        try:
            self.greet()
            while not self.done:
                command = self.next_command()
                if command is None:
                    break
                self.handle(command)
        except LineTooLong:
            try:
                self.send(self.too_long)
            except OSError:
                pass
        except (OSError, ValueError):     # 연결 리셋, 보내기 시간 초과, 서버 종료 중 닫힌 소켓
            pass
        finally:
            self.log("연결 끝")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def greet(self) -> None:
        raise NotImplementedError

    def handle(self, command) -> None:
        raise NotImplementedError


def _number(text: str) -> Optional[int]:
    """"12" → 12. 숫자(ASCII)만으로 된 글자가 아니면 None."""
    return int(text) if text.isascii() and text.isdigit() else None


# -----------------------------------------------------------------------------
# SMTP (RFC 5321, AUTH는 RFC 4954)
# -----------------------------------------------------------------------------
ADDRESS_ARG = re.compile(r"(FROM|TO):\s*<([^>]*)>\s*(.*)", re.IGNORECASE)


class SmtpSession(Session):
    name = "SMTP"
    too_long = "500 Line too long"

    def greet(self) -> None:
        self.authed = False
        self.reset()
        self.send(f"220 {HOSTNAME} ESMTP wireshrimp test server")

    def reset(self) -> None:
        self.mail_from: Optional[str] = None
        self.rcpts: list[str] = []

    def handle(self, line: str) -> None:
        verb, _, arg = line.partition(" ")
        verb, arg = verb.upper(), arg.strip()
        mech, _, initial = arg.partition(" ")
        self.log("> " + (f"AUTH {mech} ****" if verb == "AUTH" and initial else line))
        if verb == "EHLO":
            self.reset()
            self.send(f"250-{HOSTNAME} Hello {arg or 'there'}", f"250-SIZE {MAX_MESSAGE}",
                      "250-8BITMIME", "250-AUTH PLAIN LOGIN", "250 HELP")
        elif verb == "HELO":
            self.reset()
            self.send(f"250 {HOSTNAME} Hello {arg or 'there'}")
        elif verb == "MAIL":
            self.mail(arg)
        elif verb == "RCPT":
            self.rcpt(arg)
        elif verb == "DATA":
            self.data()
        elif verb == "AUTH":
            self.auth(mech.upper(), initial.strip())
        elif verb in ("RSET", "NOOP"):
            if verb == "RSET":
                self.reset()
            self.send("250 OK")
        elif verb == "HELP":
            self.send("214 Commands: EHLO HELO MAIL RCPT DATA RSET NOOP VRFY HELP AUTH QUIT")
        elif verb == "VRFY":
            self.send("252 Cannot VRFY user, but will accept message")
        elif verb == "STARTTLS":
            self.send("454 TLS not available (plaintext test server)")
        elif verb == "QUIT":
            self.send(f"221 {HOSTNAME} Bye")
            self.done = True
        else:
            self.send("500 Command not recognized")

    def mail(self, arg: str) -> None:
        m = ADDRESS_ARG.fullmatch(arg)
        size = re.search(r"\bSIZE=(\d+)", m.group(3), re.IGNORECASE) if m else None
        if not m or m.group(1).upper() != "FROM":
            self.send("501 Syntax: MAIL FROM:<address>")
        elif size and int(size.group(1)) > MAX_MESSAGE:
            self.send("552 Message size exceeds fixed maximum message size")
        else:
            self.reset()
            self.mail_from = m.group(2)
            self.send("250 OK")

    def rcpt(self, arg: str) -> None:
        m = ADDRESS_ARG.fullmatch(arg)
        if self.mail_from is None:
            self.send("503 Need MAIL command")
        elif not m or m.group(1).upper() != "TO" or not m.group(2):
            self.send("501 Syntax: RCPT TO:<address>")
        elif len(self.rcpts) >= 100:
            self.send("452 Too many recipients")
        else:
            self.rcpts.append(m.group(2))
            self.send("250 OK")

    def data(self) -> None:
        if not self.rcpts:
            self.send("503 Need RCPT command")
            return
        self.send("354 End data with <CR><LF>.<CR><LF>")
        lines, size = [], 0
        while True:
            line = self.reader.readline(MAX_LINE + 1)
            if not line:                       # 끝 표시 전에 끊김
                self.done = True
                return
            if line == b".\r\n":
                break
            if line.startswith(b"."):          # 점으로 시작하는 줄에 붙인 점 하나(dot-stuffing)를 뗀다
                line = line[1:]
            size += len(line)
            if size <= MAX_MESSAGE:
                lines.append(line)
        if len(lines) >= 2 and lines[-1] == b"\r\n" and not lines[-2].endswith(b"\r\n"):
            lines.pop()        # LF 줄 끝 파일 뒤에 curl이 붙인 끝 표시 "\r\n.\r\n"의 앞 CRLF (빈 줄이 아님)
        message = b"".join(lines)
        number = None if size > MAX_MESSAGE else self.mailbox.add(message)
        if size > MAX_MESSAGE:
            self.send("552 Message size exceeds fixed maximum message size")
        elif number is None:
            self.send("452 Mailbox full")
        else:
            self.log(f"메일 받음 {len(message)} bytes → 메일함 {number}번 "
                     f"(POP3 RETR {number}, IMAP UID FETCH {number})")
            self.send(f"250 OK: queued as {number}")
        self.reset()

    def auth(self, mech: str, initial: str) -> None:
        if self.authed:
            self.send("503 Already authenticated")
            return
        if mech == "PLAIN":                    # base64("authzid \0 user \0 password")
            answer = self.decode(initial) if initial else self.challenge("")
            parts = answer.split(b"\0") if answer is not None else None
            ok = parts is not None and parts[1:] == [USER.encode(), PASSWORD.encode()]
        elif mech == "LOGIN":                  # 334 Username: → 334 Password: (base64)
            user = self.decode(initial) if initial else self.challenge("VXNlcm5hbWU6")
            password = self.challenge("UGFzc3dvcmQ6") if user is not None else None
            answer = password
            ok = (user, password) == (USER.encode(), PASSWORD.encode())
        else:
            self.send("504 Unrecognized authentication type")
            return
        if answer is None:                     # 취소(*), 잘못된 base64, 끊김 → 이미 응답함
            return
        self.authed = ok
        self.log("AUTH 성공" if ok else "AUTH 실패")
        self.send("235 Authentication successful" if ok else "535 Authentication credentials invalid")

    def challenge(self, prompt: str) -> Optional[bytes]:
        """334 prompt를 보내고 받은 base64 한 줄을 풀어 돌려준다. 취소·잘못된 값·끊김이면 None."""
        self.send(f"334 {prompt}")
        line = self.readline()
        if line is None:
            self.done = True
            return None
        if line == b"*":
            self.send("501 Authentication cancelled")
            return None
        return self.decode(line.decode("ascii", "replace"))

    def decode(self, text: str) -> Optional[bytes]:
        try:
            return base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            self.send("501 Invalid base64 data")
            return None


# -----------------------------------------------------------------------------
# POP3 (RFC 1939, CAPA는 RFC 2449)
# -----------------------------------------------------------------------------
class Pop3Session(Session):
    name = "POP3"
    too_long = "-ERR Line too long"

    def greet(self) -> None:
        self.user: Optional[str] = None
        self.mails: Optional[list[bytes]] = None     # 로그인한 뒤의 메일함 (세션 동안 번호가 그대로)
        self.deleted: set[int] = set()
        self.send("+OK wireshrimp POP3 test server ready")

    def handle(self, line: str) -> None:
        verb, _, arg = line.partition(" ")
        verb = verb.upper()
        self.log("> " + ("PASS ****" if verb == "PASS" else line))
        if verb == "CAPA":
            self.send("+OK Capability list follows", "USER", "UIDL", "TOP", ".")
        elif verb == "QUIT":
            self.send("+OK Bye")
            self.done = True
        elif self.mails is None:
            self.authorization(verb, arg)
        else:
            self.transaction(verb, arg.strip())

    def authorization(self, verb: str, arg: str) -> None:
        if verb == "USER":
            self.user = arg.strip()
            self.send("+OK")
        elif verb == "PASS":                   # 비밀번호 안 공백도 비밀번호의 일부 (RFC 1939)
            if self.user is None:
                self.send("-ERR USER first")
            elif (self.user, arg) == (USER, PASSWORD):
                self.mails = self.mailbox.snapshot()
                self.log(f"로그인 성공 (메일 {len(self.mails)}통)")
                self.send(f"+OK Logged in, {len(self.mails)} messages")
            else:
                self.user = None
                self.log("로그인 실패")
                self.send("-ERR Authentication failed")
        elif verb == "STLS":
            self.send("-ERR TLS not available (plaintext test server)")
        elif verb in ("APOP", "AUTH"):
            self.send(f"-ERR {verb} not supported, use USER and PASS")
        else:
            self.send("-ERR Log in first (USER, PASS)")

    def transaction(self, verb: str, arg: str) -> None:
        mails = self.mails
        live = [n for n in range(1, len(mails) + 1) if n not in self.deleted]
        if verb == "STAT":
            self.send(f"+OK {len(live)} {sum(len(mails[n - 1]) for n in live)}")
        elif verb in ("LIST", "UIDL"):             # 크기 또는 고유 ID
            value = {n: len(mails[n - 1]) if verb == "LIST" else f"{self.mailbox.uidvalidity}.{n}"
                     for n in live}
            if arg:
                n = self.message(arg)
                if n:
                    self.send(f"+OK {n} {value[n]}")
            else:
                self.send(f"+OK {len(live)} messages", *(f"{n} {v}" for n, v in value.items()), ".")
        elif verb == "RETR":
            n = self.message(arg)
            if n:
                self.send_mail(f"+OK {len(mails[n - 1])} octets", mails[n - 1])
        elif verb == "TOP":                    # TOP 번호 줄수: 헤더 + 본문 앞 몇 줄
            num, _, count = arg.partition(" ")
            n = self.message(num)
            lines = _number(count.strip())
            if n and lines is None:
                self.send("-ERR Syntax: TOP message lines")
            elif n:
                head, sep, body = mails[n - 1].partition(b"\r\n\r\n")
                self.send_mail("+OK", head + sep + b"".join(body.splitlines(True)[:lines]))
        elif verb == "DELE":
            n = self.message(arg)
            if n:
                self.deleted.add(n)
                self.send(f"+OK Message {n} deleted (kept on the test server)")
        elif verb == "RSET":
            self.deleted.clear()
            self.send(f"+OK {len(mails)} messages")
        elif verb == "NOOP":
            self.send("+OK")
        elif verb in ("USER", "PASS"):
            self.send("-ERR Already logged in")
        else:
            self.send("-ERR Unknown command")

    def message(self, arg: str) -> Optional[int]:
        """메일 번호. 없는 번호·이 세션에서 지운 메일이면 -ERR을 보내고 None."""
        n = _number(arg)
        if n is not None and 1 <= n <= len(self.mails) and n not in self.deleted:
            return n
        self.send("-ERR No such message")
        return None

    def send_mail(self, first: str, mail: bytes) -> None:
        """여러 줄 응답: 첫 줄 + 메일(점으로 시작하는 줄은 점을 하나 더) + "." 한 줄을 한 번에."""
        body = re.sub(rb"(?m)^\.", b"..", mail)
        if body and not body.endswith(b"\r\n"):
            body += b"\r\n"
        self.sock.sendall(first.encode() + b"\r\n" + body + b".\r\n")


# -----------------------------------------------------------------------------
# IMAP (RFC 3501의 일부)
# -----------------------------------------------------------------------------
LITERAL = re.compile(r"\{(\d+)(\+?)\}$")      # 줄 끝의 literal 표시 {크기}, {크기+}(기다리지 않음)
FETCH_ITEM = re.compile(r"BODY(\.PEEK)?\[(HEADER|TEXT)?\]|RFC822(\.HEADER|\.TEXT|\.SIZE)?"
                        r"|FLAGS|UID|INTERNALDATE", re.IGNORECASE)
SELECT_FLAGS = r"* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)"


def imap_tokens(text: str) -> list[str]:
    """IMAP 명령 → 토큰. 괄호·대괄호 안 공백에서는 나누지 않고, 따옴표 문자열은 따옴표를 벗긴다.

    예) 'A3 UID FETCH 1 (UID BODY[])' → ['A3', 'UID', 'FETCH', '1', '(UID BODY[])']
        'A4 LIST "" *'                 → ['A4', 'LIST', '', '*']
    """
    tokens: list[str] = []
    cur, depth, i = "", 0, 0
    while i < len(text):
        ch = text[i]
        if ch == '"' and depth == 0 and not cur:      # 따옴표 문자열 (역슬래시 다음 글자는 그대로)
            i += 1
            while i < len(text) and text[i] != '"':
                if text[i] == "\\" and i + 1 < len(text):
                    i += 1
                cur += text[i]
                i += 1
            tokens.append(cur)
            cur = ""
        elif ch == " " and depth == 0:
            if cur:
                tokens.append(cur)
            cur = ""
        else:
            depth = max(0, depth + (ch in "([") - (ch in ")]"))
            cur += ch
        i += 1
    if cur:
        tokens.append(cur)
    return tokens


def parse_set(text: str, last: int) -> list[int]:
    """번호 묶음("1", "2:4", "3:*", "*", "1,3") → 1~last 안의 번호 목록. 모양이 틀리면 ValueError."""
    numbers: set[int] = set()
    for part in text.split(","):
        lo, colon, hi = part.partition(":")
        a = _set_number(lo, last)
        b = _set_number(hi, last) if colon else a
        numbers.update(range(max(min(a, b), 1), min(max(a, b), last) + 1))
    return sorted(numbers)


def _set_number(text: str, last: int) -> int:
    """번호 묶음 안의 숫자 하나. "*"는 마지막 번호. 0이나 숫자가 아니면 ValueError."""
    if text == "*":
        return last
    n = _number(text)
    if not n:
        raise ValueError(f"bad message number: {text!r}")
    return n


def _text(token) -> str:
    return token.decode("utf-8", "replace") if isinstance(token, bytes) else token


class ImapSession(Session):
    name = "IMAP"
    too_long = "* BAD Line too long"

    def greet(self) -> None:
        self.logged_in = False
        self.selected: Optional[list[bytes]] = None    # SELECT한 순간의 메일함
        self.send("* OK wireshrimp IMAP4rev1 test server ready")

    def next_command(self):
        """명령 하나 → 토큰 목록. literal은 "+" 응답을 보내고 그 크기만큼 받아 bytes 토큰으로."""
        tokens: list = []
        while True:
            line = self.readline()
            if line is None:
                return None
            text = line.decode("utf-8", "replace")
            m = LITERAL.search(text)
            tokens += imap_tokens(text[:m.start()] if m else text)
            if not m:
                return tokens
            size = int(m.group(1))
            if size > MAX_MESSAGE:
                self.send("* BYE Literal too big")
                return None
            if not m.group(2):
                self.send("+ Ready for literal data")
            data = self.reader.read(size)
            if len(data) < size:
                return None
            tokens.append(data)

    def handle(self, tokens: list) -> None:
        shown = [t if isinstance(t, str) else "{%d}" % len(t) for t in tokens]   # literal은 크기만
        if len(shown) > 3 and shown[1].upper() == "LOGIN":
            shown[3:] = ["****"]
        self.log("> " + " ".join(shown))
        tag = tokens[0] if tokens and isinstance(tokens[0], str) and tokens[0] else "*"
        command = tokens[1].upper() if len(tokens) > 1 and isinstance(tokens[1], str) else ""
        args = tokens[2:]
        uid = command == "UID"
        if uid:
            command = _text(args[0]).upper() if args else ""
            args = args[1:]
            if command not in ("FETCH", "SEARCH"):
                self.send(f"{tag} BAD UID needs FETCH or SEARCH")
                return
        if not command or tag == "*":
            self.send(f"{tag} BAD Missing tag or command")
        elif command == "CAPABILITY":
            self.send("* CAPABILITY IMAP4rev1", f"{tag} OK CAPABILITY completed")
        elif command == "NOOP":
            self.send(f"{tag} OK NOOP completed")
        elif command == "LOGOUT":
            self.send("* BYE wireshrimp IMAP server logging out", f"{tag} OK LOGOUT completed")
            self.done = True
        elif command == "STARTTLS":
            self.send(f"{tag} BAD STARTTLS not available (plaintext test server)")
        elif command == "AUTHENTICATE":
            self.send(f"{tag} NO AUTHENTICATE not supported, use LOGIN")
        elif command == "LOGIN":
            self.login(tag, args)
        elif not self.logged_in:
            self.send(f"{tag} BAD Log in first")
        elif command in ("SELECT", "EXAMINE"):
            self.select(tag, command, args)
        elif command in ("LIST", "LSUB"):
            self.list(tag, command, args)
        elif command == "APPEND":
            self.append(tag, args)
        elif command not in ("FETCH", "SEARCH", "CLOSE", "UNSELECT", "EXPUNGE"):
            self.send(f"{tag} BAD Unknown command")
        elif self.selected is None:
            self.send(f"{tag} BAD No mailbox selected")
        elif command == "FETCH":
            self.fetch(tag, args, uid)
        elif command == "SEARCH":                      # 조건과 상관없이 전부 (번호 = UID)
            found = " ".join(str(n) for n in range(1, len(self.selected) + 1))
            self.send(f"* SEARCH {found}".rstrip(), f"{tag} OK SEARCH completed")
        else:                                          # CLOSE, UNSELECT, EXPUNGE
            if command != "EXPUNGE":
                self.selected = None
            self.send(f"{tag} OK {command} completed")

    def login(self, tag: str, args: list) -> None:
        if self.logged_in:
            self.send(f"{tag} BAD Already logged in")
        elif len(args) != 2:
            self.send(f"{tag} BAD Syntax: LOGIN user password")
        elif (_text(args[0]), _text(args[1])) == (USER, PASSWORD):
            self.logged_in = True
            self.log("로그인 성공")
            self.send(f"{tag} OK LOGIN completed")
        else:
            self.log("로그인 실패")
            self.send(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials")

    def select(self, tag: str, command: str, args: list) -> None:
        if len(args) != 1 or _text(args[0]).upper() != "INBOX":
            self.selected = None
            self.send(f"{tag} NO Mailbox does not exist (only INBOX)")
            return
        self.selected = self.mailbox.snapshot()
        n = len(self.selected)
        mode = "READ-WRITE" if command == "SELECT" else "READ-ONLY"
        self.send(SELECT_FLAGS, f"* {n} EXISTS", "* 0 RECENT",
                  f"* OK [UIDVALIDITY {self.mailbox.uidvalidity}] UIDs valid",
                  f"* OK [UIDNEXT {n + 1}] Predicted next UID",
                  f"{tag} OK [{mode}] {command} completed")

    def list(self, tag: str, command: str, args: list) -> None:
        if len(args) != 2:
            self.send(f"{tag} BAD Syntax: {command} reference mailbox")
            return
        pattern = _text(args[0]) + _text(args[1])
        lines = []
        if not _text(args[1]):                         # 이름 구분자 묻기
            lines.append(f"* {command} " + r'(\Noselect) "/" ""')
        elif re.fullmatch(re.escape(pattern).replace(r"\*", ".*").replace("%", "[^/]*"),
                          "INBOX", re.IGNORECASE):
            lines.append(f"* {command} " + r'(\HasNoChildren) "/" INBOX')
        self.send(*lines, f"{tag} OK {command} completed")

    def append(self, tag: str, args: list) -> None:
        if len(args) < 2 or not isinstance(args[-1], bytes):
            self.send(f"{tag} BAD Syntax: APPEND mailbox {{size}}")
        elif _text(args[0]).upper() != "INBOX":
            self.send(f"{tag} NO [TRYCREATE] Mailbox does not exist (only INBOX)")
        else:
            number = self.mailbox.add(args[-1])
            if number is None:
                self.send(f"{tag} NO Mailbox full")
            else:
                self.log(f"메일 받음 {len(args[-1])} bytes → 메일함 {number}번")
                self.send(f"{tag} OK APPEND completed")

    def fetch(self, tag: str, args: list, uid: bool) -> None:
        name = "UID FETCH" if uid else "FETCH"
        if len(args) != 2 or not all(isinstance(a, str) for a in args):
            self.send(f"{tag} BAD Syntax: {name} set items")
            return
        try:
            numbers = parse_set(args[0], len(self.selected))
        except ValueError:
            self.send(f"{tag} BAD Invalid message set")
            return
        spec = args[1][1:-1] if args[1].startswith("(") and args[1].endswith(")") else args[1]
        items = imap_tokens(spec)
        if [i.upper() for i in items] == ["FAST"]:
            items = ["FLAGS", "INTERNALDATE", "RFC822.SIZE"]
        if not items or not all(FETCH_ITEM.fullmatch(i) for i in items):
            self.send(f"{tag} BAD Unsupported FETCH item")
            return
        if uid and "UID" not in (i.upper() for i in items):
            items.insert(0, "UID")
        out = b""
        for n in numbers:                              # 번호 = UID (지우지 않으므로)
            parts = [self.fetch_item(item.upper(), n, self.selected[n - 1]) for item in items]
            out += b"* %d FETCH (" % n + b" ".join(parts) + b")\r\n"
        self.sock.sendall(out + f"{tag} OK {name} completed\r\n".encode())

    @staticmethod
    def fetch_item(item: str, n: int, mail: bytes) -> bytes:
        if item == "UID":
            return b"UID %d" % n
        if item == "FLAGS":
            return rb"FLAGS (\Seen)"
        if item == "INTERNALDATE":
            return b'INTERNALDATE "22-Nov-2026 12:00:00 +0900"'
        if item == "RFC822.SIZE":
            return b"RFC822.SIZE %d" % len(mail)
        head, sep, body = mail.partition(b"\r\n\r\n")
        section = item.replace(".PEEK", "")            # 응답에는 BODY.PEEK[]도 BODY[]로
        data = {"BODY[]": mail, "RFC822": mail, "BODY[HEADER]": head + sep,
                "RFC822.HEADER": head + sep, "BODY[TEXT]": body, "RFC822.TEXT": body}[section]
        return section.encode() + b" {%d}\r\n" % len(data) + data


# -----------------------------------------------------------------------------
# 서버: 포트 세 개를 열고, 연결마다 스레드 하나
# -----------------------------------------------------------------------------
SESSIONS = {"smtp": SmtpSession, "pop3": Pop3Session, "imap": ImapSession}


class MailServer:
    """start()로 포트를 열고 받는 스레드를 띄운다. stop()은 포트·연결·스레드를 모두 정리한다.

    ports: {"smtp": 포트, "pop3": 포트, "imap": 포트} — 0이면 OS가 빈 포트를 고른다 (테스트용)
    """

    def __init__(self, ports: dict[str, int], host: str = "0.0.0.0", log: Optional[Log] = None,
                 mailbox: Optional[Mailbox] = None) -> None:
        self.host = host
        self.wanted = dict(ports)
        self.ports: dict[str, int] = {}                 # 실제로 연 포트
        self.mailbox = mailbox or Mailbox()
        self.listeners: dict[socket.socket, str] = {}
        self.failed: Optional[str] = None               # 열지 못한 프로토콜 이름
        self._print = log or (lambda text: print(text, flush=True))
        self._log_lock = threading.Lock()
        # 종료 신호: stop()이 [1]에 한 바이트 쓰면 [0]이 계속 읽을 수 있는 상태가 되어,
        # [0]을 같이 기다리던 받는 스레드·연결 스레드가 모두 깨어나 끝난다
        self._stop: Optional[tuple[socket.socket, socket.socket]] = None
        self._acceptor: Optional[threading.Thread] = None
        self._sessions: dict[threading.Thread, socket.socket] = {}
        self._lock = threading.Lock()

    def log(self, text: str) -> None:
        with self._log_lock:
            self._print(time.strftime("%H:%M:%S ") + text)

    def start(self) -> None:
        for name, port in self.wanted.items():
            try:
                sock = socket.create_server((self.host, port))
            except OSError:
                self.failed = name
                self._close_listeners()
                raise
            sock.setblocking(False)
            self.listeners[sock] = name
            self.ports[name] = sock.getsockname()[1]
        self._stop = socket.socketpair()
        self._acceptor = threading.Thread(target=self._accept_loop, name="mail-accept", daemon=True)
        self._acceptor.start()

    def _accept_loop(self) -> None:
        stop = self._stop[0]
        with selectors.DefaultSelector() as sel:
            sel.register(stop, selectors.EVENT_READ)
            for sock in self.listeners:
                sel.register(sock, selectors.EVENT_READ)
            while True:
                for key, _ in sel.select():
                    if key.fileobj is stop:
                        return
                    try:
                        conn, addr = key.fileobj.accept()
                    except OSError:
                        continue
                    conn.settimeout(IDLE_TIMEOUT)       # 윈도우는 받은 소켓도 non-blocking을 물려받음
                    self._spawn(conn, addr, self.listeners[key.fileobj])

    def _spawn(self, conn: socket.socket, addr, name: str) -> None:
        session = SESSIONS[name](conn, addr, self.mailbox, self.log, self._stop[0])
        thread = threading.Thread(target=self._run, args=(session,), daemon=True,
                                  name=f"mail-{name}-{addr[1]}")
        with self._lock:
            self._sessions[thread] = conn
        thread.start()

    def _run(self, session: Session) -> None:
        try:
            session.run()
        finally:
            session.close()
            with self._lock:
                self._sessions.pop(threading.current_thread(), None)

    def stop(self) -> None:
        if self._acceptor is None:                     # 시작 전이거나 이미 멈춤
            self._close_listeners()
            return
        self._stop[1].send(b"x")
        self._acceptor.join(timeout=2)
        self._acceptor = None
        self._close_listeners()
        with self._lock:
            sessions = list(self._sessions.items())
        for thread, conn in sessions:
            thread.join(timeout=1)
            if thread.is_alive():                      # 보내기에서 막힘 (상대가 읽지 않음) → 끊어서 끝낸다
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                thread.join(timeout=1)
        for sock in self._stop:
            sock.close()

    def _close_listeners(self) -> None:
        for sock in self.listeners:
            sock.close()


def local_ips() -> list[str]:
    """이 PC의 IPv4 주소 (127.x 제외), 기본 경로의 주소가 맨 앞. curl의 서버IP 자리 안내용."""
    first: list[str] = []
    try:                                               # 기본 경로의 주소 (UDP connect는 패킷을 보내지 않음)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            first.append(s.getsockname()[0])
    except OSError:
        pass
    others: set[str] = set()
    try:
        others.update(info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET))
    except OSError:
        pass
    ips = first + sorted(others - set(first))
    return [ip for ip in ips if not ip.startswith("127.") and ip != "0.0.0.0"]


def _bind_error(e: OSError, name: Optional[str], port: Optional[int]) -> str:
    where = f"{name.upper()} {port}번 포트" if name else "포트"
    if e.errno in (errno.EACCES, errno.EPERM, getattr(errno, "WSAEACCES", -1)):
        return (f"{where}를 열 권한이 없습니다 (리눅스는 1024 미만 포트에 sudo 필요).\n"
                f"  → sudo로 실행하거나: python3 tools/mail_server.py --smtp 2525 --pop3 2110 --imap 2143\n"
                f"    분석기에는 --port smtp=2525,pop3=2110,imap=2143")
    if e.errno in (errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", -1)):
        return f"{where}를 이미 다른 프로그램이 쓰고 있습니다.\n  → 다른 포트를 고르세요 (예: --{name or 'smtp'} 숫자)"
    return f"{where}를 열 수 없습니다: {e}"


def _banner(server: MailServer) -> list[str]:
    ports = server.ports
    ips = local_ips() if server.host in ("", "0.0.0.0") else [server.host]
    ip = ips[0] if ips else "서버IP"
    pop3 = "" if ports["pop3"] == DEFAULT_PORTS["pop3"] else f":{ports['pop3']}"
    imap = "" if ports["imap"] == DEFAULT_PORTS["imap"] else f":{ports['imap']}"
    lines = [f"메일 테스트 서버 시작 — 계정 {USER} / {PASSWORD}, 메일함 {len(server.mailbox.snapshot())}통",
             f"  SMTP {ports['smtp']}  POP3 {ports['pop3']}  IMAP {ports['imap']}  (받는 주소 {server.host})",
             f"  이 PC의 IP: {', '.join(ips) or '모름'}",
             "  분석기는 다른 PC에서 실행 (같은 PC면 lo로만 오가서 캡처에 안 잡힘)"]
    if ports != DEFAULT_PORTS:
        lines.append("  분석기 옵션: --port " + ",".join(f"{n}={p}" for n, p in ports.items()))
    lines += [f"  curl smtp://{ip}:{ports['smtp']} --mail-from a@test.local --mail-rcpt b@test.local -T mail.txt",
              f"  curl pop3://{ip}{pop3}/1 -u {USER}:{PASSWORD}",
              f'  curl "imap://{ip}{imap}/INBOX;UID=1" -u {USER}:{PASSWORD}',
              "  다른 PC에서 접속이 안 되면 방화벽에서 이 포트(또는 python)를 허용하세요. 끝내려면 Ctrl+C"]
    return lines


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python3 tools/mail_server.py",
                                description="평문 SMTP·POP3·IMAP 테스트 서버 (분석기 시연용 트래픽 발생). "
                                            f"계정 {USER} / {PASSWORD}, 메일 1통이 미리 들어 있음")
    for name, port in DEFAULT_PORTS.items():
        p.add_argument(f"--{name}", type=int, default=port, metavar="PORT",
                       help=f"{name.upper()} 포트 (기본 {port}, sudo 없이 띄우려면 {NO_SUDO_PORTS[name]})")
    p.add_argument("--bind", default="0.0.0.0", metavar="IP",
                   help="받을 주소 (기본 0.0.0.0 = 이 PC의 모든 IPv4 주소)")
    args = p.parse_args(argv)
    ports = {name: getattr(args, name) for name in DEFAULT_PORTS}
    for name, port in ports.items():
        if not 0 <= port <= 65535:
            p.error(f"--{name} 포트는 0~65535 (0 = 빈 포트 아무거나)")

    server = MailServer(ports, host=args.bind)
    try:
        server.start()
    except OSError as e:
        print(_bind_error(e, server.failed, ports.get(server.failed or "")), file=sys.stderr)
        return 1
    saved = _catch_stop_signals()
    try:
        for line in _banner(server):
            print(line, flush=True)
        while True:                # 윈도우에서도 Ctrl+C가 먹도록 짧게 자며 기다린다
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("종료합니다.", flush=True)
    finally:
        server.stop()
        _restore_signals(saved)
    return 0


def _catch_stop_signals() -> dict:
    """SIGINT(Ctrl+C)·SIGTERM(kill)이 오면 KeyboardInterrupt로 정리하고 끝나게 한다 → 바꾸기 전 처리기.

    신호 처리기는 메인 스레드에서만 바꿀 수 있다 → 다른 스레드에서 main()을 부르면 그대로 둔다.
    """
    if threading.current_thread() is not threading.main_thread():
        return {}
    saved = {}
    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", None)):
        if sig is not None:
            saved[sig] = signal.signal(sig, signal.default_int_handler)
    return saved


def _restore_signals(saved: dict) -> None:
    for sig, handler in saved.items():
        if handler is not None:            # 파이썬 밖(C)에서 정한 처리기는 None으로 돌아온다 → 그대로 둠
            signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(main())
