# =============================================================================
# 담당자  : B
# 맡은 기능: e-mail 해석 (DESIGN 7.6) — 선택
#            - SMTP: EHLO/HELO, MAIL FROM, RCPT TO, DATA, QUIT, STARTTLS, AUTH / 3자리 응답 코드,
#              여러 줄 응답(250-), DATA 안 메일 헤더(From, To, Subject, Date)와 본문 길이
#            - POP3: USER, PASS, STAT, LIST, RETR, DELE, QUIT / +OK, -ERR
#              CAPA·LIST·UIDL·RETR·TOP의 +OK 뒤 여러 줄은 '.' 줄까지, RETR·TOP 응답은 메일 헤더 표시
#            - IMAP: 태그 + 명령(LOGIN, SELECT, FETCH, LOGOUT) / 태그 없는 응답(* 3 EXISTS),
#              태그 응답(OK/NO/BAD), 계속 응답(+)
#              {N} literal은 바이트 수로 센다 (양방향, 세그먼트를 걸쳐도). 클라이언트의 {N}은 서버의
#              "+"를 받은 뒤에 오고 ({N+}는 바로), FETCH BODY[]·RFC822 literal과 APPEND literal은 메일 헤더 표시
#            - 한 세그먼트의 여러 줄은 줄마다 해석. 세그먼트 끝에서 잘린 줄은 다음 세그먼트 앞에 붙여 해석
#            - 메일 내용(SMTP DATA ~ '.', POP3 RETR·TOP, IMAP literal)은 conn_key별로 기억해 세그먼트를
#              걸쳐 이어 읽는다. 끝 표시(\r\n.\r\n)가 세그먼트 경계에서 잘려도 잡는다
#            - 응답이 어느 명령의 것인지는 보낸 순서로 짝짓는다 (SMTP·POP3 파이프라이닝, IMAP은 태그)
#            - STARTTLS(POP3는 STLS)를 서버가 받아들이면(220 / +OK / 태그 OK) 그 연결의 이후 세그먼트는
#              모두 "TLS (암호화 시작) N bytes"로 표시하고 해석 중단 (conn_key별로 이 파일 안에서 기억)
#            - 비밀번호는 **** : POP3 PASS·APOP·AUTH, IMAP LOGIN 비밀번호·AUTHENTICATE 줄,
#              SMTP AUTH 초기 응답과 334 뒤에 보내는 줄 (잘린 줄은 내용을 보이지 않음)
#            - 빈 데이터, 줄 단위로 읽을 첫 줄에 제어 문자가 섞인 데이터(바이너리)는 ValueError → [DATA]
#            - 화면에 찍는 값은 제어 문자를 \xNN으로 바꾸고 너무 길면 자른다. 줄이 많으면 MAX_ITEMS개까지
#            - 연결 상태는 MAX_CONNS개까지만 기억 (가장 오래 안 쓴 연결부터 잊음)
#            - 한계: parse_app()은 Seq를 모르므로 재전송 세그먼트를 한 번 더 읽는다.
#              캡처 전에 시작된 연결은 그때까지의 상태(DATA 중, literal 중 …)를 모른다
# 완료 기준: SMTP·POP3·IMAP 명령·응답이 AppInfo로 나오고 비밀번호가 가려진다.
# =============================================================================
from __future__ import annotations

import re
from collections import OrderedDict, deque
from typing import Callable, Optional

from ..models import AppInfo, ConnKey

MAX_CONNS = 256          # 상태를 기억할 연결 수. 넘으면 가장 오래 안 쓴 연결부터 잊는다
MAX_PENDING = 64         # SMTP·POP3: 응답을 기다리는 명령 수 (파이프라이닝)
MAX_LINE = 4096          # 다음 세그먼트까지 들고 있을 잘린 줄 최대 바이트 (넘으면 앞부분 + 뒷부분)
KEEP_TAIL = 256          # 긴 줄에서 남길 뒷부분 (IMAP literal 표시 {N}은 줄 끝에 있다)
MAX_ITEMS = 20           # 세그먼트 하나에서 찍을 줄 수 (summary 포함). 넘으면 나머지는 개수만
MAX_SHOW = 200           # 화면 한 줄 최대 글자 수
MAX_HEADERS = 10         # 메일 하나에서 기억할 From·To·Subject·Date 헤더 수
MAX_VALUE = 1000         # 헤더 값 최대 글자 수 (접힌 줄을 이어 붙여도)
MAX_LITERAL = 2 ** 32 - 1    # IMAP literal 크기 상한 (RFC 3501 number는 32비트)

SECRET = "****"
NEST = "  "              # 메일 내용·여러 줄 응답의 안쪽 줄 들여쓰기
TLS_TEXT = "TLS (암호화 시작)"
MAIL_HEADERS = ("from", "to", "subject", "date")     # 메일 내용에서 보여 줄 헤더

_CONTROL = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")   # \t \n \r를 뺀 제어 문자
_SMTP_REPLY = re.compile(r"([0-9]{3})([ -]|$)(.*)", re.S)     # 코드, '-'면 줄이 더 옴, 문구
_POP3_STATUS = re.compile(r"(\+OK|-ERR)(?: (.*))?", re.S | re.I)
_IMAP_STATUS = ("OK", "NO", "BAD", "PREAUTH", "BYE")
_HEADER = re.compile(r"([!-9;-~]+):(.*)", re.S)               # 메일 헤더 "이름: 값" (RFC 5322)
_LITERAL = re.compile(r"(~?)\{([0-9]{1,10})(\+?)\}$")          # IMAP literal 표시 {N} {N+} ~{N}
# literal 앞 FETCH 항목: 메일 전체 / 메일 헤더. 그 밖의 literal(BODY[TEXT], BODY[1] …)은 크기만
_FETCH_MAIL = re.compile(r"(?:^|[ (])(?:BODY\[\]|BINARY\[\]|RFC822)(?:<0>)? ~?\{[0-9]+\}$", re.I)
_FETCH_HEADER = re.compile(r"(?:^|[ (])(?:BODY\[HEADER(?:\.FIELDS(?:\.NOT)? \([^)]*\))?\]"
                           r"|RFC822\.HEADER)(?:<0>)? ~?\{[0-9]+\}$", re.I)


def parse_smtp(conn_key: ConnKey, data: bytes, from_client: bool) -> AppInfo:
    """SMTP 세그먼트 → AppInfo(name="SMTP").

    summary·lines: 줄마다 한 줄 (명령·응답 그대로, AUTH 인증 정보는 ****).
                   354 뒤 메일 내용은 "메일 내용 N bytes" + 헤더 + "메일 N bytes, body: N bytes" + "."
    fields 키: from_client, tls, commands([{verb, arg}]), replies([{code, more, text}]),
              mails([{headers, size, body_len}] — 크기는 메일이 끝난 세그먼트에서만, 아니면 None)
    빈 데이터, 첫 줄이 글자가 아닌 데이터는 ValueError.
    """
    return _parse("SMTP", _smtp_line, conn_key, data, from_client)


def parse_pop3(conn_key: ConnKey, data: bytes, from_client: bool) -> AppInfo:
    """POP3 세그먼트 → AppInfo(name="POP3").

    fields 키: from_client, tls, commands([{verb, arg}]), replies([{status("+OK"/"-ERR"/None), text}]),
              mails(RETR·TOP 응답의 메일)
    """
    return _parse("POP3", _pop3_line, conn_key, data, from_client)


def parse_imap(conn_key: ConnKey, data: bytes, from_client: bool) -> AppInfo:
    """IMAP 세그먼트 → AppInfo(name="IMAP").

    fields 키: from_client, tls, commands([{tag, command, arg}]),
              replies([{tag("*"/"+"/태그), status(OK/NO/BAD/PREAUTH/BYE 또는 None), text}]),
              mails(FETCH BODY[]·RFC822 literal, APPEND literal의 메일)
    """
    return _parse("IMAP", _imap_line, conn_key, data, from_client)


def reset_state() -> None:
    """기억한 연결 상태를 모두 지운다 (테스트용)."""
    _conns.clear()


# -----------------------------------------------------------------------------
# 연결별 상태
# -----------------------------------------------------------------------------
class _Mail:
    """메일 내용(헤더 + 본문)을 줄 단위로 읽는다. 세그먼트를 걸쳐 이어 읽는다.

    dot=True : SMTP DATA, POP3 RETR·TOP — '.' 한 줄(.\\r\\n)로 끝, 점으로 시작하는 줄은 앞 점 하나를 빼고 센다
    dot=False: IMAP literal — 바이트 수로 끝 (literal을 다 읽으면 finish())
    크기는 메일 서버가 받는 크기와 같게 센다 (tools/mail_server.py와 같음): '.' 줄 앞까지(마지막 줄의
    CRLF 포함). 단 LF 줄 끝 파일 뒤에 curl이 끝 표시로 붙인 CRLF(빈 줄이 아님)는 뺀다
    → curl -T mail.txt는 파일 크기·MAIL FROM SIZE= 와 같은 값
    """

    def __init__(self, label: str, dot: bool, reply: bool = False):
        self.label = label           # "메일" / "메일 앞부분"(POP3 TOP) / "메일 헤더"(IMAP BODY[HEADER])
        self.dot = dot
        self.reply = reply           # SMTP DATA: 메일 끝에 서버가 응답(250)한다
        self.done = False
        self.in_header = True
        self.header_bytes = 0        # 헤더 + 헤더 끝 빈 줄
        self.body_bytes = 0
        self.headers: list[list[str]] = []    # 보여 줄 헤더 [이름, 값] (나온 순서)
        self.folding: Optional[list[str]] = None   # 다음 줄이 접힌 줄이면 이어 붙일 헤더
        self.in_field = False        # 바로 앞 줄이 헤더 줄 (공백으로 시작하는 줄 = 접힌 줄)
        self.part = b""              # 세그먼트 끝에서 잘린 줄 (앞부분 MAX_LINE까지)
        self.part_len = 0
        self.part_last = b""
        self.prev_crlf = True        # 바로 앞 줄이 CRLF로 끝났는지
        self.added_crlf: Optional[str] = None   # 마지막 줄이 curl이 붙인 CRLF로 보이면 그 줄을 센 곳

    def feed(self, data: bytes, pos: int, end: int, out: _Out) -> int:
        """data[pos:end]를 읽는다. dot 모드에서 '.' 줄을 만나면 done=True, 그 줄 뒤 위치를 돌려준다."""
        while pos < end:
            nl = data.find(b"\n", pos, end)
            if nl < 0:
                self._keep(data[pos:end])
                return end
            piece = data[pos:nl + 1]
            pos = nl + 1
            if self.part_len:                 # 앞 세그먼트에서 잘린 줄 + 이번 조각
                whole = len(self.part) == self.part_len
                head = (self.part + piece)[:MAX_LINE] if whole else self.part
                length = self.part_len + len(piece)
                crlf = piece.endswith(b"\r\n") or (piece == b"\n" and self.part_last == b"\r")
                self.part, self.part_len, self.part_last = b"", 0, b""
            else:
                head, length, crlf = piece[:MAX_LINE], len(piece), piece.endswith(b"\r\n")
            if self.dot and length == 3 and head == b".\r\n":
                self.done = True
                self._close(out)
                return pos
            self._line(head, length, crlf, out)
        return pos

    def finish(self, out: _Out) -> None:
        """literal 끝: 마지막 줄이 줄 끝 없이 끝났어도 한 줄로 센다."""
        if self.part_len:
            head, length = self.part, self.part_len
            self.part, self.part_len, self.part_last = b"", 0, b""
            self._line(head, length, False, out)
        self.done = True
        self._close(out)

    def info(self) -> dict:
        headers: dict = {}
        for name, value in self.headers:
            key = name.capitalize()
            headers[key] = f"{headers[key]}, {value}" if key in headers else value
        return {"headers": headers,
                "size": self.header_bytes + self.body_bytes if self.done else None,
                "body_len": self.body_bytes if self.done else None}

    def _keep(self, piece: bytes) -> None:
        if len(self.part) == self.part_len:
            self.part = (self.part + piece)[:MAX_LINE]
        self.part_len += len(piece)
        self.part_last = piece[-1:]

    def _line(self, head: bytes, length: int, crlf: bool, out: _Out) -> None:
        size = length - 1 if self.dot and head.startswith(b".") else length    # dot-stuffing
        blank = head in (b"\r\n", b"\n")
        in_header = self.in_header
        if in_header:
            text = _text(head)
            field = _HEADER.match(text)
            if blank:                                    # 헤더 끝 빈 줄
                self._end_header(out)
            elif text[:1] in (" ", "\t") and self.in_field:   # 앞 헤더가 접혀 이어짐
                if self.folding is not None:
                    self.folding[1] = (self.folding[1] + " " + text.strip())[:MAX_VALUE]
            elif field:
                self.in_field = True
                self.folding = None
                if field[1].lower() in MAIL_HEADERS and len(self.headers) < MAX_HEADERS:
                    self.folding = [field[1], field[2].strip()[:MAX_VALUE]]
                    self.headers.append(self.folding)
            else:                                        # 헤더 모양이 아닌 줄 → 헤더 없이 본문 시작
                self._end_header(out)
                in_header = False
        if in_header:
            self.header_bytes += size
        else:
            self.body_bytes += size
        self.added_crlf = ("header" if in_header else "body") if head == b"\r\n" and not self.prev_crlf \
            else None
        self.prev_crlf = crlf

    def _end_header(self, out: _Out) -> None:
        self.in_header = False
        self.folding = None
        for name, value in self.headers:
            out.add(NEST + _show(f"{name}: {value}"))

    def _close(self, out: _Out) -> None:
        if self.in_header:
            self._end_header(out)
        if self.dot and self.added_crlf == "header":
            self.header_bytes -= 2
        elif self.dot and self.added_crlf == "body":
            self.body_bytes -= 2
        size = self.header_bytes + self.body_bytes
        if self.label == "메일 헤더":
            out.add(NEST + f"메일 헤더 {size} bytes")
        else:
            out.add(NEST + f"{self.label} {size} bytes, body: {self.body_bytes} bytes")


class _Literal:
    """IMAP literal 하나: kind "mail"/"header"(메일 헤더 표시) "plain"(크기만) "secret"(비밀번호)."""

    def __init__(self, kind: str, size: int):
        self.kind = kind
        self.total = size
        self.left = size
        self.mail: Optional[_Mail] = None


class _Side:
    """연결의 한쪽 방향(그쪽이 보내는 데이터)의 상태."""

    def __init__(self):
        self.carry = b""                          # 앞 세그먼트 끝에서 잘린 줄
        self.mail: Optional[_Mail] = None         # 읽는 중인 메일 내용 (SMTP DATA, POP3 RETR·TOP)
        self.listing = False                      # POP3 여러 줄 응답(CAPA·LIST·UIDL) 읽는 중
        self.literal: Optional[_Literal] = None   # IMAP: 읽는 중인 literal
        self.wait: Optional[_Literal] = None      # IMAP 클라이언트: 서버의 "+"를 기다리는 literal
        self.in_line = False                      # IMAP: literal 뒤 같은 줄이 이어짐
        self.cmd = ""                             # IMAP 클라이언트: 보내는 중인 명령 (LOGIN, APPEND …)
        self.tag = ""


class _Conn:
    def __init__(self):
        self.client = _Side()
        self.server = _Side()
        self.tls = False                          # STARTTLS·STLS 수락 → 이후 모두 암호화
        self.auth = None                          # AUTH 진행 중 (IMAP은 AUTHENTICATE 태그) → 클라이언트 줄 ****
        self.tls_tag: Optional[str] = None        # IMAP: STARTTLS 태그 (그 태그의 OK를 기다림)
        self.pending: deque = deque(maxlen=MAX_PENDING)   # SMTP·POP3: 응답을 기다리는 명령 (보낸 순서)


_conns: OrderedDict[tuple[str, ConnKey], _Conn] = OrderedDict()


def _state(name: str, conn_key: ConnKey) -> _Conn:
    key = (name, conn_key)
    st = _conns.get(key)
    if st is None:
        st = _conns[key] = _Conn()
        if len(_conns) > MAX_CONNS:
            _conns.popitem(last=False)            # 가장 오래 안 쓴 연결
    else:
        _conns.move_to_end(key)
    return st


class _Out:
    """세그먼트 하나의 해석 결과(화면 줄, fields)를 모은다."""

    def __init__(self, from_client: bool):
        self.items: list[str] = []
        self.mails: list[_Mail] = []
        self.fields: dict = {"from_client": from_client, "tls": False,
                             "commands": [], "replies": [], "mails": []}

    def add(self, text: str) -> None:
        self.items.append(text)

    def touch(self, mail: _Mail) -> None:
        if all(m is not mail for m in self.mails):
            self.mails.append(mail)

    def app(self, name: str, lead: Optional[str] = None) -> AppInfo:
        items = ([lead] if lead is not None else []) + self.items or ["(줄 끝)"]
        if len(items) > MAX_ITEMS:
            items = items[:MAX_ITEMS] + [f"… {len(items) - MAX_ITEMS}줄 더 (모두 {len(items)}줄)"]
        self.fields["mails"] = [m.info() for m in self.mails]
        return AppInfo(name=name, summary=items[0], lines=items[1:], fields=self.fields)


# -----------------------------------------------------------------------------
# 세그먼트 → 줄 (세 프로토콜 공통)
# -----------------------------------------------------------------------------
LineHandler = Callable[[_Conn, _Side, bool, bytes, _Out], None]


def _parse(name: str, on_line: LineHandler, conn_key: ConnKey, data: bytes,
           from_client: bool) -> AppInfo:
    if not data:
        raise ValueError(f"{name}: 빈 데이터")
    st = _state(name, conn_key)
    out = _Out(from_client)
    if st.tls:
        out.fields["tls"] = True
        return out.app(name, f"{TLS_TEXT} {len(data)} bytes")
    side = st.client if from_client else st.server
    if side.mail is None and side.literal is None:
        _check_text(name, side.carry, data)       # 상태를 바꾸기 전에 검사

    pos, lead = 0, None
    if side.literal is not None:                  # IMAP literal 가운데에서 시작
        kind = side.literal.kind
        pos = _read_literal(side, data, 0, out, lead=True)
        lead = (f"메일 내용 {pos} bytes" if kind in ("mail", "header")
                else SECRET if kind == "secret" else f"literal {pos} bytes")
    elif side.mail is not None:                   # 메일 내용(SMTP DATA, POP3 RETR) 가운데에서 시작
        pos = _read_mail(st, side, data, 0, out)
        lead = f"메일 내용 {pos} bytes"
    elif side.listing:
        lead = "(여러 줄 응답 이어짐)"

    n = len(data)
    while pos < n:
        if st.tls:                                # STARTTLS 수락 뒤 같은 세그먼트에 남은 바이트
            out.fields["tls"] = True
            out.add(f"{TLS_TEXT} {n - pos} bytes")
            break
        if side.literal is not None:
            pos = _read_literal(side, data, pos, out)
        elif side.mail is not None:
            pos = _read_mail(st, side, data, pos, out)
        else:
            nl = data.find(b"\n", pos)
            if nl < 0:                            # 줄이 다음 세그먼트로 이어짐 → 다음에 붙여서 해석
                side.carry = _bounded(side.carry + data[pos:])
                out.add(f"(줄이 다음 세그먼트로 이어짐: 이 세그먼트에 {n - pos} bytes)")
                break
            line, side.carry = side.carry + data[pos:nl + 1], b""
            pos = nl + 1
            on_line(st, side, from_client, line, out)
    return out.app(name, lead)


def _read_mail(st: _Conn, side: _Side, data: bytes, pos: int, out: _Out) -> int:
    mail = side.mail
    out.touch(mail)
    pos = mail.feed(data, pos, len(data), out)
    if mail.done:
        out.add(".")
        side.mail = None
        if mail.reply:
            st.pending.append(".")                # 메일 끝에 대한 서버 응답(250)과 짝
    else:
        out.add("(메일이 다음 세그먼트로 이어짐)")
    return pos


def _read_literal(side: _Side, data: bytes, pos: int, out: _Out, lead: bool = False) -> int:
    lit = side.literal
    end = pos + min(lit.left, len(data) - pos)
    if lit.kind in ("mail", "header"):
        if lit.mail is None:
            lit.mail = _Mail("메일" if lit.kind == "mail" else "메일 헤더", dot=False)
        out.touch(lit.mail)
        lit.mail.feed(data, pos, end, out)
    elif lit.kind == "plain" and lit.left == lit.total and not lead:
        out.add(NEST + f"literal {lit.total} bytes")
    lit.left -= end - pos
    if lit.left == 0:
        if lit.mail is not None:
            lit.mail.finish(out)
        side.literal = None
        side.in_line = True                       # literal 뒤 같은 줄이 이어진다
    else:
        what = "메일" if lit.mail is not None else "literal"
        out.add(f"({what}이 다음 세그먼트로 이어짐: {lit.total - lit.left}/{lit.total} bytes)")
    return end


def _start_literal(side: _Side, lit: _Literal) -> None:
    if lit.total:
        side.literal = lit
    else:
        side.in_line = True                       # 빈 literal {0}: 바로 같은 줄이 이어진다


# -----------------------------------------------------------------------------
# SMTP
# -----------------------------------------------------------------------------
def _smtp_line(st: _Conn, side: _Side, from_client: bool, line: bytes, out: _Out) -> None:
    text = _text(line)
    if from_client:
        if st.auth:                               # 334 뒤 = AUTH 인증 정보 (base64)
            out.add(SECRET)
            out.fields["commands"].append({"verb": None, "arg": SECRET})
            return
        verb, _, arg = text.partition(" ")
        shown = text
        if verb.upper() == "AUTH":
            mech, _, initial = arg.partition(" ")
            if initial.strip():                   # 초기 응답 (AUTH PLAIN base64)
                arg = f"{mech} {SECRET}"
                shown = f"{verb} {arg}"
            st.auth = bool(mech)
        out.add(_show(shown) if shown else "(빈 줄)")
        out.fields["commands"].append({"verb": verb.upper() or None, "arg": arg or None})
        st.pending.append(verb.upper())
        return

    out.add(_show(text) if text else "(빈 줄)")
    m = _SMTP_REPLY.fullmatch(text)
    if m is None:                                 # 응답 코드로 시작하지 않는 줄
        out.fields["replies"].append({"code": None, "more": False, "text": text})
        return
    code, more = int(m[1]), m[2] == "-"
    out.fields["replies"].append({"code": code, "more": more, "text": m[3]})
    if more or code == 334:                       # 여러 줄 응답의 앞줄 / AUTH 다음 단계 요구
        return
    cmd = st.pending.popleft() if st.pending else None    # 이 응답이 답하는 명령 (처음 220은 없음)
    if cmd == "AUTH":
        st.auth = False
    if code == 354:                               # DATA 수락 → 클라이언트가 메일 내용을 보냄
        st.client.mail = _Mail("메일", dot=True, reply=True)
    elif cmd == "STARTTLS" and code == 220:
        st.tls = True


# -----------------------------------------------------------------------------
# POP3
# -----------------------------------------------------------------------------
def _pop3_line(st: _Conn, side: _Side, from_client: bool, line: bytes, out: _Out) -> None:
    text = _text(line)
    if from_client:
        if st.auth:                               # AUTH(SASL) 인증 정보 (base64)
            out.add(SECRET)
            out.fields["commands"].append({"verb": None, "arg": SECRET})
            return
        verb, _, arg = text.partition(" ")
        cmd = verb.upper()
        masked = arg
        if cmd == "PASS" and arg:
            masked = SECRET
        elif cmd == "APOP" and " " in arg:        # APOP 이름 digest
            masked = f"{arg.split(' ', 1)[0]} {SECRET}"
        elif cmd == "AUTH" and arg:
            mech, _, initial = arg.partition(" ")
            if initial.strip():
                masked = f"{mech} {SECRET}"
            st.auth = True
        shown = text if masked == arg else f"{verb} {masked}"
        out.add(_show(shown) if shown else "(빈 줄)")
        out.fields["commands"].append({"verb": cmd or None, "arg": masked or None})
        st.pending.append((cmd, bool(arg)))
        return

    if side.listing:                              # 여러 줄 응답: '.' 줄까지
        if line in (b".\r\n", b".\n"):
            out.add(".")
            side.listing = False
        else:
            out.add(NEST + _show(text))
        return
    out.add(_show(text) if text else "(빈 줄)")
    m = _POP3_STATUS.fullmatch(text)
    if m is None:                                 # AUTH 도전(+ …) 등 — 명령과 짝짓지 않음
        out.fields["replies"].append({"status": None, "text": text})
        return
    status = m[1].upper()
    out.fields["replies"].append({"status": status, "text": m[2] or ""})
    cmd = st.pending.popleft() if st.pending else None    # 처음 인사말은 명령이 없음
    if cmd is None:
        return
    verb, has_arg = cmd
    if verb == "AUTH":
        st.auth = False
    if status != "+OK":
        return
    if verb == "STLS":
        st.tls = True
    elif verb in ("RETR", "TOP"):
        side.mail = _Mail("메일" if verb == "RETR" else "메일 앞부분", dot=True)
    elif verb == "CAPA" or (verb in ("LIST", "UIDL") and not has_arg):
        side.listing = True


# -----------------------------------------------------------------------------
# IMAP
# -----------------------------------------------------------------------------
def _imap_line(st: _Conn, side: _Side, from_client: bool, line: bytes, out: _Out) -> None:
    text = _text(line)
    cont, side.in_line = side.in_line, False      # literal 뒤 같은 줄의 나머지인지
    if from_client:
        kind = _imap_client(st, side, text, cont, out)
    else:
        kind = _imap_server(st, text, cont, out)
    m = _LITERAL.search(text)
    if m and int(m[2]) <= MAX_LITERAL:            # 줄 끝 {N}: 다음 N바이트는 literal
        lit = _Literal(kind, int(m[2]))
        if from_client and not m[3]:
            side.wait = lit                       # 동기 literal: 서버의 "+"를 받은 뒤에 보낸다
        else:
            _start_literal(side, lit)


def _imap_client(st: _Conn, side: _Side, text: str, cont: bool, out: _Out) -> str:
    """클라이언트 줄을 찍고, 줄 끝 literal의 종류를 돌려준다."""
    if cont:                                      # literal 뒤 같은 명령 줄이 이어짐
        rest = text.lstrip(" ")
        if side.cmd == "LOGIN":                   # 사용자 이름 literal 뒤 = 비밀번호
            if rest:
                out.add(SECRET)
            return "secret"
        if rest:
            out.add(_show(rest))
        return "mail" if side.cmd == "APPEND" else "plain"
    if st.auth is not None:                       # AUTHENTICATE 인증 정보 (base64)
        out.add(SECRET)
        out.fields["commands"].append({"tag": None, "command": None, "arg": SECRET})
        return "secret"

    tag, _, rest = text.partition(" ")
    command, _, args = rest.partition(" ")
    cmd = command.upper()
    if cmd == "UID":                              # UID FETCH·SEARCH·STORE·COPY …
        sub, _, args = args.partition(" ")
        command, cmd = f"{command} {sub}", f"UID {sub.upper()}"
    side.cmd, side.tag = cmd, tag
    kind, masked = "plain", args
    if cmd == "LOGIN":
        end = _astring_end(args)
        if end:                                   # 사용자 이름이 줄 안에 있음 → 그 뒤는 비밀번호
            kind = "secret"
            if args[end:].strip():
                masked = f"{args[:end]} {SECRET}"
    elif cmd == "AUTHENTICATE":
        mech, _, initial = args.partition(" ")
        if initial.strip():                       # SASL-IR 초기 응답
            masked = f"{mech} {SECRET}"
        kind = "secret"
        st.auth = tag
    elif cmd == "STARTTLS":
        st.tls_tag = tag
    elif cmd == "APPEND":
        kind = "plain" if _LITERAL.fullmatch(args) else "mail"   # 메일함 이름 literal / 메일
    shown = text if masked == args else f"{tag} {command} {masked}"
    out.add(_show(shown) if shown else "(빈 줄)")
    out.fields["commands"].append({"tag": tag or None, "command": cmd or None, "arg": masked or None})
    return kind


def _imap_server(st: _Conn, text: str, cont: bool, out: _Out) -> str:
    """서버 줄을 찍고, 줄 끝 literal의 종류를 돌려준다."""
    if cont:                                      # literal 뒤 같은 응답 줄이 이어짐 (")" 등)
        rest = text.lstrip(" ")
        if rest:
            out.add(_show(rest))
        return _fetch_kind(text)
    out.add(_show(text) if text else "(빈 줄)")
    client = st.client
    if text.startswith("+"):                      # 계속 응답: literal을 보내라 / AUTHENTICATE 도전
        out.fields["replies"].append({"tag": "+", "status": None, "text": text[1:].strip()})
        if client.wait is not None:
            _start_literal(client, client.wait)
            client.wait = None
        return "plain"
    tag, _, rest = text.partition(" ")
    word, _, more = rest.partition(" ")
    status = word.upper() if word.upper() in _IMAP_STATUS else None
    out.fields["replies"].append({"tag": tag, "status": status, "text": more if status else rest})
    if tag != "*" and status is not None:         # 태그 응답 = 그 태그의 명령이 끝남
        if tag == st.tls_tag:
            st.tls_tag = None
            st.tls = status == "OK"
        if tag == st.auth:
            st.auth = None
        if client.wait is not None and tag == client.tag:     # literal을 보내기 전에 거절됨
            client.wait = None
    return _fetch_kind(text)


def _fetch_kind(text: str) -> str:
    if _FETCH_MAIL.search(text):
        return "mail"
    if _FETCH_HEADER.search(text):
        return "header"
    return "plain"


def _astring_end(s: str) -> int:
    """IMAP astring(atom 또는 "따옴표 문자열") 하나가 끝나는 위치. literal({N})이거나 비었으면 0."""
    if not s or s[0] == "{" or s.startswith("~{"):
        return 0
    if s[0] == '"':
        i = 1
        while i < len(s):
            if s[i] == "\\":
                i += 2
            elif s[i] == '"':
                return i + 1
            else:
                i += 1
        return len(s)
    end = s.find(" ")
    return len(s) if end < 0 else end


# -----------------------------------------------------------------------------
# 공통 도우미
# -----------------------------------------------------------------------------
def _check_text(name: str, carry: bytes, data: bytes) -> None:
    """줄 단위로 읽을 첫 줄에 제어 문자(바이너리)가 섞였으면 ValueError (TLS 등 → [DATA])."""
    nl = data.find(b"\n")
    first = carry + (data if nl < 0 else data[:nl + 1])
    bad = _CONTROL.search(first)
    if bad:
        raise ValueError(f"{name}: 첫 줄에 제어 문자 0x{bad.group()[0]:02x} (글자가 아닌 데이터)")


def _bounded(buf: bytes) -> bytes:
    """다음 세그먼트까지 들고 있을 잘린 줄: 너무 길면 앞부분과 뒷부분만."""
    return buf if len(buf) <= MAX_LINE else buf[:MAX_LINE - KEEP_TAIL] + buf[-KEEP_TAIL:]


def _text(line: bytes) -> str:
    """줄 끝(\\r\\n 또는 \\n)을 떼고 글자로. UTF-8이 아닌 바이트는 �로."""
    if line.endswith(b"\n"):
        line = line[:-2] if line.endswith(b"\r\n") else line[:-1]
    return line.decode("utf-8", errors="replace")


def _show(text: str) -> str:
    """화면용: 제어 문자(터미널 색·커서를 바꿀 수 있음, C1 포함)는 \\xNN으로, 너무 길면 … 로 자른다."""
    safe = "".join(ch if ch == "\t" or not (ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F)
                   else f"\\x{ord(ch):02x}" for ch in text)
    return safe if len(safe) <= MAX_SHOW else safe[:MAX_SHOW] + "…"
