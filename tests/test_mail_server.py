# =============================================================================
# 메일 테스트 서버(tools/mail_server.py) 단위 테스트 (#15)
# - localhost 빈 포트(0)에 서버를 띄우고, curl이 보내는 순서·모양 그대로 소켓으로 대화해 응답 bytes를 본다
#   (윈도우 curl 8.22.0으로 실제로 주고받은 것: EHLO mail.txt, AUTH PLAIN → 334, CAPA → USER → PASS
#    → RETR 1, A001 CAPABILITY → A002 LOGIN → A003 SELECT INBOX → A004 UID FETCH 1 BODY[] …)
# - 표준 라이브러리 클라이언트(smtplib·poplib·imaplib)로도 확인한다
# - 테스트마다 서버를 새로 띄우고, 끝나면 연결·포트·스레드가 남지 않았는지 본다 (CI: 우분투, sudo 없음)
# =============================================================================
import contextlib
import errno
import imaplib
import importlib.util
import io
import pathlib
import poplib
import smtplib
import socket
import threading
import unittest
from unittest import mock

# tools/는 패키지가 아니라서 CI의 "모듈 불러오기" 단계와 같은 방법으로 불러온다
_TOOL = pathlib.Path(__file__).resolve().parents[1] / "tools" / "mail_server.py"
_spec = importlib.util.spec_from_file_location("tools.mail_server", _TOOL)
ms = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ms)

HOST = "127.0.0.1"
TIMEOUT = 5
FIRST = ms.FIRST_MAIL

# curl -T mail.txt가 DATA 뒤에 보낸 세그먼트 그대로 (LF 줄 끝 파일 172 bytes + curl이 붙인 \r\n.\r\n)
CURL_DATA = (b"From: a@test.local\nTo: b@test.local\nSubject: wireshrimp SMTP test\n"
             b"Date: Mon, 23 Nov 2026 10:00:00 +0900\n\nHello from curl.\n"
             b"This mail.txt has LF line endings like on Ubuntu.\n\r\n.\r\n")


def mail_threads() -> list[str]:
    return [t.name for t in threading.enumerate() if t.name.startswith("mail-")]


class Conn:
    """명령 한 줄씩 보내고 응답을 받는 소켓 클라이언트 (curl처럼)."""

    def __init__(self, port: int) -> None:
        self.sock = socket.create_connection((HOST, port), timeout=TIMEOUT)
        self.rfile = self.sock.makefile("rb")

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def line(self) -> bytes:
        return self.rfile.readline()

    def ask(self, command: bytes) -> bytes:
        """명령 한 줄을 보내고 응답 한 줄."""
        self.send(command + b"\r\n")
        return self.line()

    def until(self, prefix: bytes) -> list[bytes]:
        """prefix로 시작하는 줄까지 읽은 줄 목록 (여러 줄 응답)."""
        lines = []
        while not lines or not lines[-1].startswith(prefix):
            line = self.line()
            if not line:
                raise AssertionError(f"서버가 연결을 끊음: {lines}")
            lines.append(line)
        return lines

    def read(self, n: int) -> bytes:
        return self.rfile.read(n)

    def closed_by_server(self) -> bool:
        return self.rfile.readline() == b""

    def close(self) -> None:
        self.rfile.close()
        self.sock.close()


class ServerCase(unittest.TestCase):
    """테스트마다 새 서버 (메일함도 1통부터). 끝나면 stop() 뒤 포트·스레드가 남지 않았는지 확인."""

    def setUp(self):
        self.logs: list[str] = []
        self.server = ms.MailServer({"smtp": 0, "pop3": 0, "imap": 0}, host=HOST, log=self.logs.append)
        self.server.start()
        self.addCleanup(self.stop_server)          # addCleanup은 거꾸로 → 클라이언트를 먼저 닫고 서버를 끈다

    def stop_server(self):
        self.server.stop()
        self.assertEqual(mail_threads(), [])
        self.assertTrue(all(sock.fileno() == -1 for sock in self.server.listeners))

    def connect(self, name: str) -> Conn:
        conn = Conn(self.server.ports[name])
        self.addCleanup(conn.close)
        return conn

    def login_pop3(self) -> Conn:
        c = self.connect("pop3")
        c.line()
        c.ask(b"USER user")
        self.assertTrue(c.ask(b"PASS pass").startswith(b"+OK"))
        return c

    def login_imap(self) -> Conn:
        c = self.connect("imap")
        c.line()
        self.assertEqual(c.ask(b"A1 LOGIN user pass"), b"A1 OK LOGIN completed\r\n")
        return c

    def log_text(self) -> str:
        return "\n".join(self.logs)


# -----------------------------------------------------------------------------
# SMTP
# -----------------------------------------------------------------------------
class TestSmtp(ServerCase):
    def test_curl_session(self):
        # curl smtp://서버:2525 --mail-from a@test.local --mail-rcpt b@test.local -T mail.txt
        c = self.connect("smtp")
        self.assertEqual(c.line(), b"220 mail.test.local ESMTP wireshrimp test server\r\n")
        c.send(b"EHLO mail.txt\r\n")
        self.assertEqual(c.until(b"250 "), [
            b"250-mail.test.local Hello mail.txt\r\n", b"250-SIZE 10485760\r\n", b"250-8BITMIME\r\n",
            b"250-AUTH PLAIN LOGIN\r\n", b"250 HELP\r\n"])
        self.assertEqual(c.ask(b"MAIL FROM:<a@test.local> SIZE=172"), b"250 OK\r\n")
        self.assertEqual(c.ask(b"RCPT TO:<b@test.local>"), b"250 OK\r\n")
        self.assertEqual(c.ask(b"DATA"), b"354 End data with <CR><LF>.<CR><LF>\r\n")
        c.send(CURL_DATA)
        self.assertEqual(c.line(), b"250 OK: queued as 2\r\n")
        self.assertEqual(c.ask(b"QUIT"), b"221 mail.test.local Bye\r\n")
        self.assertTrue(c.closed_by_server())
        # 메일함에는 파일 내용 그대로 (줄 끝만 CRLF로, 끝 표시 앞 CRLF는 빈 줄로 남기지 않음)
        self.assertEqual(self.server.mailbox.snapshot()[1], CURL_DATA[:-5].replace(b"\n", b"\r\n"))
        self.assertIn("메일 받음 172 bytes → 메일함 2번", self.log_text())     # 받은 크기 = curl의 SIZE=172

    def test_dot_stuffing(self):
        # CRLF 파일이면 curl은 점으로 시작하는 줄에 점을 하나 더 붙이고, 끝 표시는 ".\r\n"만 보낸다
        c = self.connect("smtp")
        c.line()
        for command in (b"HELO mail_crlf.txt", b"MAIL FROM:<a@test.local>", b"RCPT TO:<b@test.local>"):
            self.assertTrue(c.ask(command).startswith(b"250"), command)
        self.assertTrue(c.ask(b"DATA").startswith(b"354"))
        c.send(b"Subject: dot\r\n\r\nline one\r\n..starts with a dot\r\n.\r\n")
        self.assertEqual(c.line(), b"250 OK: queued as 2\r\n")
        self.assertEqual(self.server.mailbox.snapshot()[1],
                         b"Subject: dot\r\n\r\nline one\r\n.starts with a dot\r\n")

    def test_auth_plain_like_curl(self):
        # curl -u user:pass: 초기 응답 없이 AUTH PLAIN → "334 " → base64("\0user\0pass")
        c = self.connect("smtp")
        c.line()
        c.send(b"EHLO mail.txt\r\n")
        c.until(b"250 ")
        self.assertEqual(c.ask(b"AUTH PLAIN"), b"334 \r\n")
        self.assertEqual(c.ask(b"AHVzZXIAcGFzcw=="), b"235 Authentication successful\r\n")
        self.assertEqual(c.ask(b"AUTH PLAIN AHVzZXIAcGFzcw=="), b"503 Already authenticated\r\n")
        self.assertNotIn("AHVzZXIAcGFzcw", self.log_text())     # 서버 기록에도 인증 정보는 안 남김
        self.assertIn("AUTH PLAIN ****", self.log_text())

    def test_auth_login_and_failures(self):
        c = self.connect("smtp")
        c.line()
        self.assertEqual(c.ask(b"AUTH LOGIN"), b"334 VXNlcm5hbWU6\r\n")            # "Username:"
        self.assertEqual(c.ask(b"dXNlcg=="), b"334 UGFzc3dvcmQ6\r\n")               # "Password:"
        self.assertEqual(c.ask(b"d3Jvbmc="), b"535 Authentication credentials invalid\r\n")   # "wrong"
        self.assertEqual(c.ask(b"AUTH LOGIN dXNlcg=="), b"334 UGFzc3dvcmQ6\r\n")    # 초기 응답 = 이름
        self.assertEqual(c.ask(b"cGFzcw=="), b"235 Authentication successful\r\n")
        c2 = self.connect("smtp")
        c2.line()
        self.assertEqual(c2.ask(b"AUTH PLAIN"), b"334 \r\n")
        self.assertEqual(c2.ask(b"*"), b"501 Authentication cancelled\r\n")
        self.assertEqual(c2.ask(b"AUTH PLAIN not-base64!"), b"501 Invalid base64 data\r\n")
        self.assertEqual(c2.ask(b"AUTH PLAIN dXNlcgBwYXNz"), b"535 Authentication credentials invalid\r\n")
        self.assertEqual(c2.ask(b"AUTH CRAM-MD5"), b"504 Unrecognized authentication type\r\n")

    def test_command_errors(self):
        c = self.connect("smtp")
        c.line()
        for command, reply in [
                (b"RCPT TO:<b@test.local>", b"503 Need MAIL command"),
                (b"DATA", b"503 Need RCPT command"),
                (b"MAIL a@test.local", b"501 Syntax: MAIL FROM:<address>"),
                (b"MAIL FROM:<a@test.local> SIZE=99999999", b"552 Message size exceeds fixed maximum message size"),
                (b"MAIL FROM:<a@test.local>", b"250 OK"),
                (b"RCPT b@test.local", b"501 Syntax: RCPT TO:<address>"),
                (b"STARTTLS", b"454 TLS not available (plaintext test server)"),
                (b"VRFY user", b"252 Cannot VRFY user, but will accept message"),
                (b"NOOP", b"250 OK"),
                (b"RSET", b"250 OK"),
                (b"RCPT TO:<b@test.local>", b"503 Need MAIL command"),      # RSET이 MAIL을 지움
                (b"XYZZY", b"500 Command not recognized"),
                (b"", b"500 Command not recognized")]:
            self.assertEqual(c.ask(command), reply + b"\r\n", command)
        self.assertTrue(c.ask(b"HELP").startswith(b"214 Commands: EHLO"))

    def test_smtplib(self):
        port = self.server.ports["smtp"]
        with smtplib.SMTP(HOST, port, local_hostname="ubuntu", timeout=TIMEOUT) as s:
            s.login(ms.USER, ms.PASSWORD)             # AUTH PLAIN (초기 응답 포함)
            refused = s.sendmail("a@test.local", ["b@test.local"], b"Subject: hi\r\n\r\n.dot\r\nbody\r\n")
        self.assertEqual(refused, {})
        self.assertEqual(self.server.mailbox.snapshot()[1], b"Subject: hi\r\n\r\n.dot\r\nbody\r\n")
        with smtplib.SMTP(HOST, port, local_hostname="ubuntu", timeout=TIMEOUT) as s:
            with self.assertRaises(smtplib.SMTPAuthenticationError):
                s.login(ms.USER, "wrong")


# -----------------------------------------------------------------------------
# POP3
# -----------------------------------------------------------------------------
class TestPop3(ServerCase):
    def test_curl_session(self):
        # curl pop3://서버:2110/1 -u user:pass → CAPA, USER, PASS, RETR 1, QUIT
        c = self.connect("pop3")
        self.assertEqual(c.line(), b"+OK wireshrimp POP3 test server ready\r\n")
        c.send(b"CAPA\r\n")
        self.assertEqual(c.until(b".\r\n"), [b"+OK Capability list follows\r\n", b"USER\r\n", b"UIDL\r\n",
                                             b"TOP\r\n", b".\r\n"])      # SASL이 없어 curl이 USER/PASS를 씀
        self.assertEqual(c.ask(b"USER user"), b"+OK\r\n")
        self.assertEqual(c.ask(b"PASS pass"), b"+OK Logged in, 1 messages\r\n")
        c.send(b"RETR 1\r\n")
        self.assertEqual(c.line(), b"+OK %d octets\r\n" % len(FIRST))
        self.assertEqual(c.read(len(FIRST) + 3), FIRST + b".\r\n")
        self.assertEqual(c.ask(b"QUIT"), b"+OK Bye\r\n")
        self.assertTrue(c.closed_by_server())
        self.assertIn("PASS ****", self.log_text())
        self.assertNotIn("PASS pass", self.log_text())

    def test_poplib(self):
        p = poplib.POP3(HOST, self.server.ports["pop3"], timeout=TIMEOUT)
        p.user(ms.USER)
        p.pass_(ms.PASSWORD)
        self.assertEqual(p.stat(), (1, len(FIRST)))
        self.assertEqual(p.list()[1], [b"1 %d" % len(FIRST)])
        self.assertEqual(p.uidl()[1], [b"1 %d.1" % self.server.mailbox.uidvalidity])
        self.assertEqual(b"\r\n".join(p.retr(1)[1]) + b"\r\n", FIRST)
        self.assertEqual(p.top(1, 0)[1], FIRST.split(b"\r\n\r\n")[0].split(b"\r\n") + [b""])
        p.dele(1)
        with self.assertRaises(poplib.error_proto):
            p.retr(1)                                  # 이 세션에서는 지운 것으로 보인다
        p.rset()
        self.assertEqual(p.stat()[0], 1)
        p.dele(1)
        p.quit()
        p = poplib.POP3(HOST, self.server.ports["pop3"], timeout=TIMEOUT)   # 실제로는 지우지 않음
        p.user(ms.USER)
        p.pass_(ms.PASSWORD)
        self.assertEqual(p.stat()[0], 1)
        p.quit()

    def test_retr_dot_stuffing(self):
        mail = b"Subject: dots\r\n\r\n.one dot\r\n..two dots\r\nlast"      # 마지막 줄 끝 없음
        self.server.mailbox.add(mail)
        c = self.login_pop3()
        c.send(b"RETR 2\r\n")
        self.assertEqual(c.until(b".\r\n"), [b"+OK %d octets\r\n" % len(mail), b"Subject: dots\r\n", b"\r\n",
                                             b"..one dot\r\n", b"...two dots\r\n", b"last\r\n", b".\r\n"])

    def test_errors(self):
        c = self.connect("pop3")
        c.line()
        for command, reply in [
                (b"STAT", b"-ERR Log in first (USER, PASS)"),
                (b"PASS pass", b"-ERR USER first"),
                (b"STLS", b"-ERR TLS not available (plaintext test server)"),
                (b"APOP user c4c9334bac560ecc979e58001b3e22fb", b"-ERR APOP not supported, use USER and PASS"),
                (b"USER user", b"+OK"),
                (b"PASS wrong", b"-ERR Authentication failed"),
                (b"USER user", b"+OK"),
                (b"PASS pass", b"+OK Logged in, 1 messages"),
                (b"RETR 2", b"-ERR No such message"),
                (b"RETR x", b"-ERR No such message"),
                (b"LIST 1", b"+OK 1 %d" % len(FIRST)),
                (b"TOP 1 x", b"-ERR Syntax: TOP message lines"),
                (b"PASS pass", b"-ERR Already logged in"),
                (b"XYZZY", b"-ERR Unknown command")]:
            self.assertEqual(c.ask(command), reply + b"\r\n", command)


# -----------------------------------------------------------------------------
# IMAP
# -----------------------------------------------------------------------------
class TestImap(ServerCase):
    def test_curl_session(self):
        # curl "imap://서버:2143/INBOX;UID=1" -u user:pass
        c = self.connect("imap")
        self.assertEqual(c.line(), b"* OK wireshrimp IMAP4rev1 test server ready\r\n")
        c.send(b"A001 CAPABILITY\r\n")
        self.assertEqual(c.until(b"A001 "), [b"* CAPABILITY IMAP4rev1\r\n",       # AUTH=가 없어 curl이 LOGIN을 씀
                                             b"A001 OK CAPABILITY completed\r\n"])
        self.assertEqual(c.ask(b"A002 LOGIN user pass"), b"A002 OK LOGIN completed\r\n")
        c.send(b"A003 SELECT INBOX\r\n")
        self.assertEqual(c.until(b"A003 "), [
            rb"* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)" + b"\r\n",
            b"* 1 EXISTS\r\n", b"* 0 RECENT\r\n",
            b"* OK [UIDVALIDITY %d] UIDs valid\r\n" % self.server.mailbox.uidvalidity,
            b"* OK [UIDNEXT 2] Predicted next UID\r\n",
            b"A003 OK [READ-WRITE] SELECT completed\r\n"])
        c.send(b"A004 UID FETCH 1 BODY[]\r\n")
        self.assertEqual(c.line(), b"* 1 FETCH (UID 1 BODY[] {%d}\r\n" % len(FIRST))
        self.assertEqual(c.read(len(FIRST)), FIRST)
        self.assertEqual(c.until(b"A004 "), [b")\r\n", b"A004 OK UID FETCH completed\r\n"])
        c.send(b"A005 LOGOUT\r\n")
        self.assertEqual(c.until(b"A005 "), [b"* BYE wireshrimp IMAP server logging out\r\n",
                                             b"A005 OK LOGOUT completed\r\n"])
        self.assertTrue(c.closed_by_server())
        self.assertIn("A002 LOGIN user ****", self.log_text())
        self.assertNotIn("LOGIN user pass", self.log_text())

    def test_imaplib(self):
        m = imaplib.IMAP4(HOST, self.server.ports["imap"], timeout=TIMEOUT)
        try:
            self.assertEqual(m.login(ms.USER, ms.PASSWORD)[0], "OK")      # imaplib은 비밀번호를 "따옴표"로
            self.assertEqual(m.list(), ("OK", [rb'(\HasNoChildren) "/" INBOX']))
            self.assertEqual(m.select("INBOX"), ("OK", [b"1"]))
            self.assertEqual(m.fetch("1", "(RFC822)")[1][0][1], FIRST)
            header = m.uid("FETCH", "1", "(BODY.PEEK[HEADER])")[1][0]
            self.assertEqual(header[0], b"1 (UID 1 BODY[HEADER] {%d}" % (FIRST.index(b"\r\n\r\n") + 4))
            self.assertEqual(m.search(None, "ALL"), ("OK", [b"1"]))
            appended = b"Subject: appended\r\n\r\nhi\r\n"
            self.assertEqual(m.append("INBOX", None, None, appended)[0], "OK")     # APPEND INBOX {25}
            self.assertEqual(m.select("INBOX"), ("OK", [b"2"]))
            self.assertEqual(m.fetch("2", "(BODY[TEXT])")[1][0][1], b"hi\r\n")
            self.assertEqual(m.fetch("1:*", "(UID RFC822.SIZE)")[1],
                             [b"1 (UID 1 RFC822.SIZE %d)" % len(FIRST), b"2 (UID 2 RFC822.SIZE %d)" % len(appended)])
            self.assertEqual(m.select("Sent")[0], "NO")
        finally:
            self.assertEqual(m.logout()[0], "BYE")
        self.assertIn("APPEND INBOX {%d}" % len(appended), self.log_text())    # literal은 크기만 기록

    def test_login_with_literals(self):
        # 이름·비밀번호를 literal({크기})로 보내는 클라이언트: "+" 응답을 받고 나서 내용을 보낸다
        c = self.connect("imap")
        c.line()
        self.assertEqual(c.ask(b"A1 LOGIN {4}"), b"+ Ready for literal data\r\n")
        self.assertEqual(c.ask(b"user {4}"), b"+ Ready for literal data\r\n")
        self.assertEqual(c.ask(b"pass"), b"A1 OK LOGIN completed\r\n")
        c.send(b"A2 LOGOUT\r\n")
        c.until(b"A2 ")
        self.assertIn("A1 LOGIN {4} ****", self.log_text())

    def test_errors(self):
        c = self.connect("imap")
        c.line()
        for command, reply in [
                (b"A1 SELECT INBOX", b"A1 BAD Log in first"),
                (b"A2 LOGIN user wrong", b"A2 NO [AUTHENTICATIONFAILED] Invalid credentials"),
                (b"A3 STARTTLS", b"A3 BAD STARTTLS not available (plaintext test server)"),
                (b"A4 AUTHENTICATE PLAIN", b"A4 NO AUTHENTICATE not supported, use LOGIN"),
                (b"", b"* BAD Missing tag or command"),
                (b"A5", b"A5 BAD Missing tag or command"),
                (b"A6 LOGIN user pass", b"A6 OK LOGIN completed"),
                (b"A7 LOGIN user pass", b"A7 BAD Already logged in"),
                (b"A8 FETCH 1 BODY[]", b"A8 BAD No mailbox selected"),
                (b"A9 SELECT Sent", b"A9 NO Mailbox does not exist (only INBOX)"),
                (b"B1 XYZZY", b"B1 BAD Unknown command"),
                (rb"B2 UID STORE 1 +FLAGS (\Seen)", b"B2 BAD UID needs FETCH or SEARCH"),
                (b"B3 APPEND Sent {1+}", None)]:
            if reply is None:                          # {1+}: "+" 없이 바로 보내는 literal
                c.send(command + b"\r\nx\r\n")
                self.assertEqual(c.line(), b"B3 NO [TRYCREATE] Mailbox does not exist (only INBOX)\r\n")
            else:
                self.assertEqual(c.ask(command), reply + b"\r\n", command)
        c.send(b"C1 EXAMINE inbox\r\n")
        self.assertEqual(c.until(b"C1 ")[-1], b"C1 OK [READ-ONLY] EXAMINE completed\r\n")
        for command, reply in [
                (b"C2 FETCH 0 BODY[]", b"C2 BAD Invalid message set"),
                (b"C3 FETCH 1 ENVELOPE", b"C3 BAD Unsupported FETCH item"),
                (b"C4 FETCH 5 BODY[]", b"C4 OK FETCH completed"),          # 없는 번호는 응답 없이 OK
                (b"C5 FETCH 1", b"C5 BAD Syntax: FETCH set items"),
                (b"C6 UID SEARCH ALL", b"* SEARCH 1"),
                (b"C7 CLOSE", b"C7 OK CLOSE completed"),
                (b"C8 SEARCH ALL", b"C8 BAD No mailbox selected")]:
            self.assertEqual(c.ask(command), reply + b"\r\n", command)
            if command.startswith(b"C6"):
                self.assertEqual(c.line(), b"C6 OK SEARCH completed\r\n")

    def test_line_too_long_closes(self):
        c = self.connect("imap")
        c.line()
        c.send(b"A" * (ms.MAX_LINE + 1))                # 줄 끝 없이 MAX_LINE 넘김
        self.assertEqual(c.line(), b"* BAD Line too long\r\n")
        self.assertTrue(c.closed_by_server())


class TestImapHelpers(unittest.TestCase):
    def test_tokens(self):
        self.assertEqual(ms.imap_tokens("A3 UID FETCH 1 (UID BODY[])"), ["A3", "UID", "FETCH", "1", "(UID BODY[])"])
        self.assertEqual(ms.imap_tokens('A4 LIST "" *'), ["A4", "LIST", "", "*"])
        self.assertEqual(ms.imap_tokens(r'A5 LOGIN user "p a\"ss"'), ["A5", "LOGIN", "user", 'p a"ss'])
        self.assertEqual(ms.imap_tokens("A6 FETCH 1 BODY[HEADER.FIELDS (FROM TO)]"),
                         ["A6", "FETCH", "1", "BODY[HEADER.FIELDS (FROM TO)]"])
        self.assertEqual(ms.imap_tokens("  A7   NOOP  "), ["A7", "NOOP"])

    def test_parse_set(self):
        self.assertEqual(ms.parse_set("1", 3), [1])
        self.assertEqual(ms.parse_set("2:*", 3), [2, 3])
        self.assertEqual(ms.parse_set("*", 3), [3])
        self.assertEqual(ms.parse_set("3:1,2", 3), [1, 2, 3])
        self.assertEqual(ms.parse_set("1:4294967295", 2), [1, 2])
        self.assertEqual(ms.parse_set("5", 3), [])
        self.assertEqual(ms.parse_set("1:*", 0), [])
        for bad in ("0", "x", "1:", "", "1,,2", "-1", "²"):
            with self.assertRaises(ValueError, msg=bad):
                ms.parse_set(bad, 3)


# -----------------------------------------------------------------------------
# 메일함 공유, 시작·끝
# -----------------------------------------------------------------------------
class TestSharedMailbox(ServerCase):
    def test_smtp_mail_is_read_by_pop3_and_imap(self):
        with smtplib.SMTP(HOST, self.server.ports["smtp"], local_hostname="ubuntu", timeout=TIMEOUT) as s:
            s.sendmail("a@test.local", ["user@test.local"], b"Subject: relay\n\nvia smtp\n")   # LF 줄 끝
        p = poplib.POP3(HOST, self.server.ports["pop3"], timeout=TIMEOUT)
        p.user(ms.USER)
        p.pass_(ms.PASSWORD)
        self.assertEqual(p.retr(2)[1], [b"Subject: relay", b"", b"via smtp"])
        p.quit()
        m = imaplib.IMAP4(HOST, self.server.ports["imap"], timeout=TIMEOUT)
        m.login(ms.USER, ms.PASSWORD)
        m.select("INBOX")
        self.assertEqual(m.fetch("2", "(BODY[])")[1][0][1], b"Subject: relay\r\n\r\nvia smtp\r\n")
        m.logout()

    def test_mailbox_limit(self):
        box = ms.Mailbox()
        for _ in range(ms.MAX_MAILS - 1):
            self.assertIsNotNone(box.add(b"x\r\n"))
        self.assertIsNone(box.add(b"x\r\n"))


class TestLifecycle(unittest.TestCase):
    def test_stop_closes_idle_connections(self):
        server = ms.MailServer({"smtp": 0, "pop3": 0, "imap": 0}, host=HOST, log=lambda _text: None)
        server.start()
        conns = [Conn(server.ports[name]) for name in ("smtp", "pop3", "imap")]
        for conn in conns:
            conn.line()                                # 인사만 받고 QUIT 없이 열어 둔 연결
        server.stop()
        for conn in conns:
            self.assertTrue(conn.closed_by_server())
            conn.close()
        self.assertEqual(mail_threads(), [])
        server.stop()                                  # 두 번 불러도 괜찮다

    def test_main_runs_until_ctrl_c(self):
        out = io.StringIO()
        with mock.patch.object(ms.time, "sleep", side_effect=KeyboardInterrupt), \
                contextlib.redirect_stdout(out):
            code = ms.main(["--smtp", "0", "--pop3", "0", "--imap", "0", "--bind", HOST])
        self.assertEqual(code, 0)
        text = out.getvalue()
        self.assertIn("계정 user / pass", text)
        self.assertIn("분석기 옵션: --port smtp=", text)
        self.assertIn('curl "imap://127.0.0.1:', text)
        self.assertIn("종료합니다", text)
        self.assertEqual(mail_threads(), [])

    def test_main_needs_sudo_for_low_ports(self):
        err = io.StringIO()
        denied = PermissionError(errno.EACCES, "Permission denied")
        with mock.patch.object(ms.socket, "create_server", side_effect=denied), contextlib.redirect_stderr(err):
            code = ms.main([])
        self.assertEqual(code, 1)
        self.assertIn("SMTP 25번 포트를 열 권한이 없습니다", err.getvalue())
        self.assertIn("--smtp 2525 --pop3 2110 --imap 2143", err.getvalue())
        self.assertIn("--port smtp=2525,pop3=2110,imap=2143", err.getvalue())

    def test_main_port_in_use(self):
        with socket.create_server((HOST, 0)) as busy:
            port = busy.getsockname()[1]
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = ms.main(["--smtp", "0", "--pop3", str(port), "--imap", "0", "--bind", HOST])
        self.assertEqual(code, 1)
        self.assertIn(f"POP3 {port}번 포트를 이미 다른 프로그램이 쓰고 있습니다", err.getvalue())
        self.assertEqual(mail_threads(), [])

    def test_bad_port_option(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            ms.main(["--smtp", "70000"])

    def test_local_ips(self):
        ips = ms.local_ips()
        self.assertIsInstance(ips, list)
        self.assertFalse(any(ip.startswith("127.") for ip in ips))


if __name__ == "__main__":
    unittest.main()
