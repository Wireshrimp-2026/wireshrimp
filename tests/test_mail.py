# =============================================================================
# e-mail 해석(parse_smtp·parse_pop3·parse_imap) 단위 테스트 (#14)
# - curl 8.22.0 ↔ tools/mail_server.py가 실제로 주고받은 세그먼트 bytes 그대로 (한 항목 = 세그먼트 하나)
# - STARTTLS 이후는 직접 만든 bytes (실제 서버 응답 모양 + TLS 레코드)
# - 비밀번호 가림, 여러 줄, 세그먼트를 걸친 DATA·literal, 짧거나 깨진 데이터, decode → 화면 줄
# =============================================================================
import contextlib
import io
import unittest

from src.decode import app_mail
from src.decode.app_mail import MAX_CONNS, MAX_ITEMS, SECRET, parse_imap, parse_pop3, parse_smtp
from src.decode.app_select import parse_app
from src.models import DEFAULT_PORTS, Captured
from tests.test_link_ip import eth, ipv4, tcp_header

C, S = True, False          # from_client: 클라이언트 → 서버 / 서버 → 클라이언트
SMTP_KEY = ("10.0.2.15", 51000, "192.168.0.10", 25)
POP3_KEY = ("10.0.2.15", 51001, "192.168.0.10", 110)
IMAP_KEY = ("10.0.2.15", 51002, "192.168.0.10", 143)

# ---- SMTP: curl smtp://서버:2525 --mail-from a@test.local --mail-rcpt b@test.local -T mail.txt
# mail.txt: 우분투에서 만든 파일처럼 LF 줄 끝, 172 bytes
MAIL_TXT = (b"From: a@test.local\nTo: b@test.local\nSubject: wireshrimp SMTP test\n"
            b"Date: Mon, 23 Nov 2026 10:00:00 +0900\n\nHello from curl.\n"
            b"This mail.txt has LF line endings like on Ubuntu.\n")
DATA_SEGMENT = MAIL_TXT + b"\r\n.\r\n"       # curl이 끝 표시를 붙여 한 세그먼트로 (177 bytes)
EHLO_REPLY = (b"250-mail.test.local Hello mail.txt\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n"
              b"250-AUTH PLAIN LOGIN\r\n250 HELP\r\n")
GO_AHEAD = b"354 End data with <CR><LF>.<CR><LF>\r\n"
SMTP_CURL = [
    (S, b"220 mail.test.local ESMTP wireshrimp test server\r\n"),
    (C, b"EHLO mail.txt\r\n"),               # curl은 -T 파일 이름을 EHLO에 쓴다
    (S, EHLO_REPLY),
    (C, b"MAIL FROM:<a@test.local> SIZE=172\r\n"),
    (S, b"250 OK\r\n"),
    (C, b"RCPT TO:<b@test.local>\r\n"),
    (S, b"250 OK\r\n"),
    (C, b"DATA\r\n"),
    (S, GO_AHEAD),
    (C, DATA_SEGMENT),
    (S, b"250 OK: queued as 3\r\n"),
    (C, b"QUIT\r\n"),
    (S, b"221 mail.test.local Bye\r\n"),
]
SMTP_CURL_SCREEN = [
    ["220 mail.test.local ESMTP wireshrimp test server"],
    ["EHLO mail.txt"],
    ["250-mail.test.local Hello mail.txt", "250-SIZE 10485760", "250-8BITMIME", "250-AUTH PLAIN LOGIN",
     "250 HELP"],
    ["MAIL FROM:<a@test.local> SIZE=172"],
    ["250 OK"],
    ["RCPT TO:<b@test.local>"],
    ["250 OK"],
    ["DATA"],
    ["354 End data with <CR><LF>.<CR><LF>"],
    ["메일 내용 177 bytes",
     "  From: a@test.local",
     "  To: b@test.local",
     "  Subject: wireshrimp SMTP test",
     "  Date: Mon, 23 Nov 2026 10:00:00 +0900",
     "  메일 172 bytes, body: 67 bytes",       # = 파일 크기 = MAIL FROM SIZE=172
     "."],
    ["250 OK: queued as 3"],
    ["QUIT"],
    ["221 mail.test.local Bye"],
]
# CRLF 파일: curl이 점으로 시작하는 줄에 점을 하나 더 붙임(dot-stuffing), 끝은 ".\r\n"만
CRLF_DATA = (b"From: a@test.local\r\nTo: b@test.local\r\nSubject: CRLF file with a dot line\r\n\r\n"
             b"line one\r\n..starts with a dot\r\n.\r\n")
# curl -u user:pass → AUTH PLAIN (초기 응답 없이) → 334 → base64("\0user\0pass")
AUTH_PLAIN = [(C, b"AUTH PLAIN\r\n"), (S, b"334 \r\n"), (C, b"AHVzZXIAcGFzcw==\r\n"),
              (S, b"235 Authentication successful\r\n")]
# curl --login-options AUTH=LOGIN → 334 Username: → base64(user) → 334 Password: → base64(pass)
AUTH_LOGIN = [(C, b"AUTH LOGIN\r\n"), (S, b"334 VXNlcm5hbWU6\r\n"), (C, b"dXNlcg==\r\n"),
              (S, b"334 UGFzc3dvcmQ6\r\n"), (C, b"cGFzcw==\r\n"), (S, b"235 Authentication successful\r\n")]

# ---- POP3: curl pop3://서버:2110/1 -u user:pass
FIRST_MAIL = (b"From: wireshrimp <test@test.local>\r\nTo: user <user@test.local>\r\n"
              b"Subject: wireshrimp test mail\r\nDate: Sun, 22 Nov 2026 12:00:00 +0900\r\n"
              b"Message-ID: <1@test.local>\r\n\r\nHello from the wireshrimp mail test server.\r\n"
              b"POP3 RETR 1 and IMAP UID FETCH 1 read this message.\r\n")      # 262 bytes
RETR_REPLY = b"+OK 262 octets\r\n" + FIRST_MAIL + b".\r\n"                   # 281 bytes 한 세그먼트
CAPA_REPLY = b"+OK Capability list follows\r\nUSER\r\nUIDL\r\nTOP\r\n.\r\n"
POP3_CURL = [
    (S, b"+OK wireshrimp POP3 test server ready\r\n"),
    (C, b"CAPA\r\n"),
    (S, CAPA_REPLY),
    (C, b"USER user\r\n"),
    (S, b"+OK\r\n"),
    (C, b"PASS pass\r\n"),
    (S, b"+OK Logged in, 3 messages\r\n"),
    (C, b"RETR 1\r\n"),
    (S, RETR_REPLY),
    (C, b"QUIT\r\n"),
    (S, b"+OK Bye\r\n"),
]
MAIL_HEADER_LINES = ["  From: wireshrimp <test@test.local>",
                     "  To: user <user@test.local>",
                     "  Subject: wireshrimp test mail",
                     "  Date: Sun, 22 Nov 2026 12:00:00 +0900"]
POP3_CURL_SCREEN = [
    ["+OK wireshrimp POP3 test server ready"],
    ["CAPA"],
    ["+OK Capability list follows", "  USER", "  UIDL", "  TOP", "."],
    ["USER user"],
    ["+OK"],
    ["PASS ****"],
    ["+OK Logged in, 3 messages"],
    ["RETR 1"],
    ["+OK 262 octets", *MAIL_HEADER_LINES, "  메일 262 bytes, body: 98 bytes", "."],
    ["QUIT"],
    ["+OK Bye"],
]

# ---- IMAP: curl "imap://서버:2143/INBOX;UID=1" -u user:pass
SELECT_REPLY = (b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n* 3 EXISTS\r\n* 0 RECENT\r\n"
                b"* OK [UIDVALIDITY 1795324585] UIDs valid\r\n* OK [UIDNEXT 4] Predicted next UID\r\n"
                b"A003 OK [READ-WRITE] SELECT completed\r\n")
FETCH_REPLY = (b"* 1 FETCH (UID 1 BODY[] {262}\r\n" + FIRST_MAIL
               + b")\r\nA004 OK UID FETCH completed\r\n")                     # 325 bytes 한 세그먼트
BYE_REPLY = b"* BYE wireshrimp IMAP server logging out\r\nA005 OK LOGOUT completed\r\n"
IMAP_CURL = [
    (S, b"* OK wireshrimp IMAP4rev1 test server ready\r\n"),
    (C, b"A001 CAPABILITY\r\n"),
    (S, b"* CAPABILITY IMAP4rev1\r\nA001 OK CAPABILITY completed\r\n"),
    (C, b"A002 LOGIN user pass\r\n"),
    (S, b"A002 OK LOGIN completed\r\n"),
    (C, b"A003 SELECT INBOX\r\n"),
    (S, SELECT_REPLY),
    (C, b"A004 UID FETCH 1 BODY[]\r\n"),
    (S, FETCH_REPLY),
    (C, b"A005 LOGOUT\r\n"),
    (S, BYE_REPLY),
]
FETCH_SCREEN = ["* 1 FETCH (UID 1 BODY[] {262}", *MAIL_HEADER_LINES, "  메일 262 bytes, body: 98 bytes",
                ")", "A004 OK UID FETCH completed"]
IMAP_CURL_SCREEN = [
    ["* OK wireshrimp IMAP4rev1 test server ready"],
    ["A001 CAPABILITY"],
    ["* CAPABILITY IMAP4rev1", "A001 OK CAPABILITY completed"],
    ["A002 LOGIN user ****"],
    ["A002 OK LOGIN completed"],
    ["A003 SELECT INBOX"],
    ["* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)", "* 3 EXISTS", "* 0 RECENT",
     "* OK [UIDVALIDITY 1795324585] UIDs valid", "* OK [UIDNEXT 4] Predicted next UID",
     "A003 OK [READ-WRITE] SELECT completed"],
    ["A004 UID FETCH 1 BODY[]"],
    FETCH_SCREEN,
    ["A005 LOGOUT"],
    ["* BYE wireshrimp IMAP server logging out", "A005 OK LOGOUT completed"],
]

# ---- STARTTLS 뒤 TLS 레코드 (test_tls.py와 같은 모양): ClientHello 517 bytes, ServerHello 127 bytes
CLIENT_HELLO = bytes.fromhex("16 0301 0200  01 0001fc 0303") + bytes(506)
SERVER_HELLO = bytes.fromhex("16 0303 007a  02 000076 0303") + bytes(116)
APP_DATA = bytes.fromhex("17 0303 0035") + bytes(range(0x80, 0x80 + 53))


def screen(app):
    return [app.summary] + app.lines


def replay(parser, segments, key):
    return [parser(key, data, from_client) for from_client, data in segments]


class MailTest(unittest.TestCase):
    def setUp(self):
        app_mail.reset_state()

    def assertHidden(self, secret, apps):
        for app in apps:
            self.assertNotIn(secret, repr(app))


# -----------------------------------------------------------------------------
# SMTP
# -----------------------------------------------------------------------------
class TestSmtp(MailTest):
    def test_real_bytes_sizes(self):
        # 기록한 세그먼트 크기 그대로인지 (mail-curl-segments.log)
        self.assertEqual((len(MAIL_TXT), len(DATA_SEGMENT), len(EHLO_REPLY)), (172, 177, 101))

    def test_curl_session(self):
        apps = replay(parse_smtp, SMTP_CURL, SMTP_KEY)
        self.assertEqual([screen(a) for a in apps], SMTP_CURL_SCREEN)
        self.assertEqual({a.name for a in apps}, {"SMTP"})
        self.assertEqual([a.fields["from_client"] for a in apps], [c for c, _ in SMTP_CURL])

    def test_fields(self):
        apps = replay(parse_smtp, SMTP_CURL, SMTP_KEY)
        self.assertEqual(apps[1].fields["commands"], [{"verb": "EHLO", "arg": "mail.txt"}])
        self.assertEqual(apps[3].fields["commands"],
                         [{"verb": "MAIL", "arg": "FROM:<a@test.local> SIZE=172"}])
        replies = apps[2].fields["replies"]
        self.assertEqual([(r["code"], r["more"]) for r in replies],
                         [(250, True)] * 4 + [(250, False)])
        self.assertEqual(replies[0]["text"], "mail.test.local Hello mail.txt")
        self.assertEqual(apps[8].fields["replies"],
                         [{"code": 354, "more": False, "text": "End data with <CR><LF>.<CR><LF>"}])
        self.assertEqual(apps[9].fields["mails"], [{
            "headers": {"From": "a@test.local", "To": "b@test.local", "Subject": "wireshrimp SMTP test",
                        "Date": "Mon, 23 Nov 2026 10:00:00 +0900"},
            "size": 172, "body_len": 67}])
        self.assertEqual(apps[9].fields["commands"], [])         # 메일 내용은 명령이 아님
        self.assertFalse(any(a.fields["tls"] for a in apps))

    def test_crlf_file_with_dot_stuffing(self):
        # 점 하나를 더 붙인 줄은 그 점을 빼고 센다 → 서버가 받는 크기 = 파일 크기 = SIZE=106
        replay(parse_smtp, [(C, b"DATA\r\n"), (S, GO_AHEAD)], SMTP_KEY)
        app = parse_smtp(SMTP_KEY, CRLF_DATA, C)
        self.assertEqual(screen(app), [
            "메일 내용 110 bytes", "  From: a@test.local", "  To: b@test.local",
            "  Subject: CRLF file with a dot line", "  메일 106 bytes, body: 30 bytes", "."])

    def test_pipelining(self):
        # 명령 여러 개가 한 세그먼트, 응답도 한 세그먼트 → 줄마다 해석하고 보낸 순서로 짝짓는다
        cmds = parse_smtp(SMTP_KEY, b"MAIL FROM:<a@x>\r\nRCPT TO:<b@x>\r\nRCPT TO:<c@x>\r\nDATA\r\n", C)
        self.assertEqual(screen(cmds), ["MAIL FROM:<a@x>", "RCPT TO:<b@x>", "RCPT TO:<c@x>", "DATA"])
        self.assertEqual([c["verb"] for c in cmds.fields["commands"]], ["MAIL", "RCPT", "RCPT", "DATA"])
        replies = parse_smtp(SMTP_KEY, b"250 OK\r\n250 OK\r\n550 No such user\r\n354 Go ahead\r\n", S)
        self.assertEqual([r["code"] for r in replies.fields["replies"]], [250, 250, 550, 354])
        body = parse_smtp(SMTP_KEY, b"Subject: hi\r\n\r\nhello\r\n.\r\nQUIT\r\n", C)
        self.assertEqual(screen(body), ["메일 내용 25 bytes", "  Subject: hi", "  메일 22 bytes, body: 7 bytes",
                                        ".", "QUIT"])            # 끝 표시 뒤 같은 세그먼트의 명령
        self.assertEqual(body.fields["commands"], [{"verb": "QUIT", "arg": None}])

    def test_other_commands(self):
        apps = replay(parse_smtp, [(C, b"HELO client\r\n"), (S, b"250 mail.test.local\r\n"),
                                   (C, b"RSET\r\n"), (S, b"250 OK\r\n"), (C, b"VRFY user\r\n"),
                                   (S, b"252 Cannot VRFY user\r\n"), (C, b"BOGUS\r\n"),
                                   (S, b"500 Command not recognized\r\n")], SMTP_KEY)
        self.assertEqual([a.summary for a in apps], ["HELO client", "250 mail.test.local", "RSET", "250 OK",
                                                     "VRFY user", "252 Cannot VRFY user", "BOGUS",
                                                     "500 Command not recognized"])
        self.assertEqual(apps[6].fields["commands"], [{"verb": "BOGUS", "arg": None}])

    def test_unknown_reply_line(self):
        app = parse_smtp(SMTP_KEY, b"hello there\r\n", S)       # 응답 코드로 시작하지 않음 → 그대로, code None
        self.assertEqual(screen(app), ["hello there"])
        self.assertEqual(app.fields["replies"], [{"code": None, "more": False, "text": "hello there"}])


class TestSmtpAuth(MailTest):
    def test_auth_plain_curl(self):
        apps = replay(parse_smtp, AUTH_PLAIN + [(C, b"MAIL FROM:<a@test.local> SIZE=106\r\n")], SMTP_KEY)
        self.assertEqual([screen(a) for a in apps], [
            ["AUTH PLAIN"], ["334 "], [SECRET], ["235 Authentication successful"],
            ["MAIL FROM:<a@test.local> SIZE=106"]])            # 인증이 끝나면 다시 그대로
        self.assertEqual(apps[2].fields["commands"], [{"verb": None, "arg": SECRET}])
        self.assertHidden("AHVzZXIAcGFzcw==", apps)

    def test_auth_login_curl(self):
        apps = replay(parse_smtp, AUTH_LOGIN, SMTP_KEY)
        self.assertEqual([a.summary for a in apps], ["AUTH LOGIN", "334 VXNlcm5hbWU6", SECRET,
                                                     "334 UGFzc3dvcmQ6", SECRET, "235 Authentication successful"])
        self.assertHidden("cGFzcw==", apps)

    def test_initial_response(self):
        apps = replay(parse_smtp, [(C, b"AUTH PLAIN AHVzZXIAcGFzcw==\r\n"), (S, b"235 2.7.0 Accepted\r\n"),
                                   (C, b"QUIT\r\n")], SMTP_KEY)
        self.assertEqual([a.summary for a in apps], ["AUTH PLAIN ****", "235 2.7.0 Accepted", "QUIT"])
        self.assertEqual(apps[0].fields["commands"], [{"verb": "AUTH", "arg": "PLAIN ****"}])
        self.assertHidden("AHVzZXIAcGFzcw==", apps)

    def test_wrong_password_ends_auth(self):
        apps = replay(parse_smtp, [(C, b"AUTH PLAIN\r\n"), (S, b"334 \r\n"), (C, b"AHVzZXIAd3Jvbmc=\r\n"),
                                   (S, b"535 Authentication credentials invalid\r\n"), (C, b"QUIT\r\n")],
                      SMTP_KEY)
        self.assertEqual([a.summary for a in apps], ["AUTH PLAIN", "334 ", SECRET,
                                                     "535 Authentication credentials invalid", "QUIT"])
        self.assertHidden("AHVzZXIAd3Jvbmc=", apps)

    def test_mechanism_rejected(self):
        apps = replay(parse_smtp, [(C, b"AUTH CRAM-MD5\r\n"), (S, b"504 Unrecognized authentication type\r\n"),
                                   (C, b"MAIL FROM:<a@x>\r\n")], SMTP_KEY)
        self.assertEqual(apps[2].summary, "MAIL FROM:<a@x>")


class TestSmtpDataAcrossSegments(MailTest):
    def start_data(self, key):
        replay(parse_smtp, [(S, b"220 ready\r\n"), (C, b"DATA\r\n"), (S, GO_AHEAD)], key)

    def test_split_everywhere(self):
        # 177 bytes를 어디서 둘로 잘라도 같은 결과 (끝 표시 \r\n.\r\n 안에서 잘려도)
        for cut in range(1, len(DATA_SEGMENT)):
            key = ("10.0.2.15", 52000 + cut, "192.168.0.10", 25)
            self.start_data(key)
            first = parse_smtp(key, DATA_SEGMENT[:cut], C)
            second = parse_smtp(key, DATA_SEGMENT[cut:], C)
            self.assertEqual(first.summary, f"메일 내용 {cut} bytes", cut)
            self.assertEqual(first.lines[-1], "(메일이 다음 세그먼트로 이어짐)", cut)
            self.assertEqual(second.summary, f"메일 내용 {len(DATA_SEGMENT) - cut} bytes", cut)
            self.assertEqual(second.lines[-2:], ["  메일 172 bytes, body: 67 bytes", "."], cut)
            both = first.lines + second.lines
            for line in SMTP_CURL_SCREEN[9][1:]:
                self.assertEqual(both.count(line), 1, (cut, line))
            self.assertEqual(second.fields["mails"][0]["size"], 172)
            # 메일이 끝나면 다시 명령·응답
            self.assertEqual(parse_smtp(key, b"250 OK: queued as 3\r\n", S).summary, "250 OK: queued as 3")
            self.assertEqual(parse_smtp(key, b"QUIT\r\n", C).fields["commands"], [{"verb": "QUIT", "arg": None}])

    def test_long_mail_over_several_segments(self):
        body = b"".join(b"line %03d of a long mail body\r\n" % i for i in range(150))
        mail = (b"From: a@test.local\r\nTo: b@test.local\r\nSubject: long\r\n"
                b"Date: Mon, 23 Nov 2026 10:00:00 +0900\r\n\r\n" + body + b"..dotted\r\n")
        data = mail + b".\r\n"
        segments = [data[i:i + 1448] for i in range(0, len(data), 1448)]
        self.assertEqual(len(segments), 4)
        self.start_data(SMTP_KEY)
        apps = [parse_smtp(SMTP_KEY, seg, C) for seg in segments]
        self.assertEqual(screen(apps[0]), ["메일 내용 1448 bytes", "  From: a@test.local", "  To: b@test.local",
                                           "  Subject: long", "  Date: Mon, 23 Nov 2026 10:00:00 +0900",
                                           "(메일이 다음 세그먼트로 이어짐)"])
        for app in apps[1:3]:
            self.assertEqual(screen(app), ["메일 내용 1448 bytes", "(메일이 다음 세그먼트로 이어짐)"])
        body_len = len(body) + len(b".dotted\r\n")              # 붙인 점 하나는 빼고 센다
        self.assertEqual(screen(apps[3]), [f"메일 내용 {len(segments[3])} bytes",
                                           f"  메일 {len(mail) - 1} bytes, body: {body_len} bytes", "."])
        self.assertEqual(apps[0].fields["mails"][0]["size"], None)     # 아직 끝나지 않음
        self.assertEqual(apps[3].fields["mails"][0]["headers"]["Subject"], "long")

    def test_folded_and_repeated_headers(self):
        self.start_data(SMTP_KEY)
        app = parse_smtp(SMTP_KEY, b"Subject: a long\r\n subject line\r\nX-Other: hidden\r\nTo: b@x\r\n"
                                   b"to: c@x\r\nReceived: by\r\n\tsomewhere\r\n\r\nbody\r\n.\r\n", C)
        self.assertEqual(app.lines[:3], ["  Subject: a long subject line", "  To: b@x", "  to: c@x"])
        self.assertEqual(app.fields["mails"][0]["headers"],
                         {"Subject": "a long subject line", "To": "b@x, c@x"})

    def test_no_header_and_empty_mail(self):
        self.start_data(SMTP_KEY)
        self.assertEqual(screen(parse_smtp(SMTP_KEY, b"just text\r\n.\r\n", C)),
                         ["메일 내용 14 bytes", "  메일 11 bytes, body: 11 bytes", "."])
        replay(parse_smtp, [(S, b"250 OK\r\n"), (C, b"DATA\r\n"), (S, GO_AHEAD)], SMTP_KEY)
        self.assertEqual(screen(parse_smtp(SMTP_KEY, b".\r\n", C)),
                         ["메일 내용 3 bytes", "  메일 0 bytes, body: 0 bytes", "."])

    def test_binary_inside_mail_is_counted(self):
        # 메일 내용 안의 제어 문자는 ValueError가 아님 (첫 줄 검사는 명령·응답 줄만)
        self.start_data(SMTP_KEY)
        app = parse_smtp(SMTP_KEY, b"\x00\x01\x02\r\n.\r\n", C)
        self.assertEqual(app.lines, ["  메일 5 bytes, body: 5 bytes", "."])


# -----------------------------------------------------------------------------
# POP3
# -----------------------------------------------------------------------------
class TestPop3(MailTest):
    def test_real_bytes_sizes(self):
        self.assertEqual((len(FIRST_MAIL), len(RETR_REPLY), len(CAPA_REPLY)), (262, 281, 49))

    def test_curl_retr_session(self):
        apps = replay(parse_pop3, POP3_CURL, POP3_KEY)
        self.assertEqual([screen(a) for a in apps], POP3_CURL_SCREEN)
        self.assertEqual({a.name for a in apps}, {"POP3"})
        self.assertEqual(apps[5].fields["commands"], [{"verb": "PASS", "arg": SECRET}])
        self.assertEqual(apps[8].fields["replies"], [{"status": "+OK", "text": "262 octets"}])
        self.assertEqual(apps[8].fields["mails"][0]["size"], 262)       # = "+OK 262 octets"
        self.assertHidden("pass", apps)

    def test_curl_list_and_wrong_password(self):
        listing = replay(parse_pop3, [(S, b"+OK wireshrimp POP3 test server ready\r\n"), (C, b"LIST\r\n"),
                                      (S, b"+OK 5 messages\r\n1 262\r\n2 181\r\n3 181\r\n4 106\r\n5 181\r\n.\r\n"),
                                      (C, b"QUIT\r\n"), (S, b"+OK Bye\r\n")], POP3_KEY)
        self.assertEqual(screen(listing[2]), ["+OK 5 messages", "  1 262", "  2 181", "  3 181", "  4 106",
                                              "  5 181", "."])
        self.assertEqual(screen(listing[4]), ["+OK Bye"])                # 여러 줄 응답이 끝남
        wrong = replay(parse_pop3, [(C, b"USER user\r\n"), (S, b"+OK\r\n"), (C, b"PASS wrong\r\n"),
                                    (S, b"-ERR Authentication failed\r\n")], ("10.0.2.15", 51100, "s", 110))
        self.assertEqual([a.summary for a in wrong], ["USER user", "+OK", "PASS ****",
                                                      "-ERR Authentication failed"])
        self.assertEqual(wrong[3].fields["replies"], [{"status": "-ERR", "text": "Authentication failed"}])
        self.assertHidden("wrong", wrong)

    def test_single_and_multi_line_by_command(self):
        apps = replay(parse_pop3, [
            (C, b"STAT\r\n"), (S, b"+OK 3 624\r\n"),
            (C, b"LIST 1\r\n"), (S, b"+OK 1 262\r\n"),                  # 인자가 있으면 한 줄
            (C, b"UIDL\r\n"), (S, b"+OK\r\n1 a1\r\n2 b2\r\n.\r\n"),       # 인자가 없으면 여러 줄
            (C, b"DELE 1\r\n"), (S, b"+OK message 1 deleted\r\n"),
            (C, b"RETR 9\r\n"), (S, b"-ERR no such message\r\n"),       # -ERR이면 여러 줄 아님
            (C, b"NOOP\r\n"), (S, b"+OK\r\n"),
        ], POP3_KEY)
        self.assertEqual([screen(a) for a in apps[1::2]], [
            ["+OK 3 624"], ["+OK 1 262"], ["+OK", "  1 a1", "  2 b2", "."], ["+OK message 1 deleted"],
            ["-ERR no such message"], ["+OK"]])

    def test_top(self):
        replay(parse_pop3, [(C, b"TOP 1 0\r\n")], POP3_KEY)
        app = parse_pop3(POP3_KEY, b"+OK\r\n" + FIRST_MAIL.split(b"\r\n\r\n")[0] + b"\r\n\r\n.\r\n", S)
        self.assertEqual(screen(app), ["+OK", *MAIL_HEADER_LINES, "  메일 앞부분 164 bytes, body: 0 bytes", "."])

    def test_pipelined(self):
        parse_pop3(POP3_KEY, b"STAT\r\nLIST\r\nRETR 1\r\n", C)
        app = parse_pop3(POP3_KEY, b"+OK 1 262\r\n+OK 1 messages\r\n1 262\r\n.\r\n" + RETR_REPLY, S)
        self.assertEqual(screen(app), ["+OK 1 262", "+OK 1 messages", "  1 262", ".", "+OK 262 octets",
                                       *MAIL_HEADER_LINES, "  메일 262 bytes, body: 98 bytes", "."])

    def test_retr_split_everywhere(self):
        for cut in range(1, len(RETR_REPLY)):
            key = ("10.0.2.15", 53000 + cut, "192.168.0.10", 110)
            parse_pop3(key, b"RETR 1\r\n", C)
            first = parse_pop3(key, RETR_REPLY[:cut], S)
            second = parse_pop3(key, RETR_REPLY[cut:], S)
            both = screen(first) + screen(second)
            for line in POP3_CURL_SCREEN[8]:
                self.assertEqual(both.count(line), 1, (cut, line))
            self.assertEqual(second.lines[-2:], ["  메일 262 bytes, body: 98 bytes", "."], cut)
            parse_pop3(key, b"QUIT\r\n", C)
            self.assertEqual(parse_pop3(key, b"+OK Bye\r\n", S).fields["replies"],
                             [{"status": "+OK", "text": "Bye"}], cut)

    def test_secrets(self):
        apps = replay(parse_pop3, [
            (C, b"APOP user c4c9334bac560ecc979e58001b3e22fb\r\n"), (S, b"-ERR APOP not supported\r\n"),
            (C, b"AUTH PLAIN\r\n"), (S, b"+ \r\n"), (C, b"AHVzZXIAcGFzcw==\r\n"), (S, b"+OK Logged in\r\n"),
            (C, b"AUTH PLAIN AHVzZXIAcGFzcw==\r\n"), (S, b"-ERR already authenticated\r\n"),
            (C, b"STAT\r\n"),
        ], POP3_KEY)
        self.assertEqual([a.summary for a in apps], [
            "APOP user ****", "-ERR APOP not supported", "AUTH PLAIN", "+ ", SECRET, "+OK Logged in",
            "AUTH PLAIN ****", "-ERR already authenticated", "STAT"])
        self.assertHidden("c4c9334bac", apps)
        self.assertHidden("AHVzZXIAcGFzcw==", apps)


# -----------------------------------------------------------------------------
# IMAP
# -----------------------------------------------------------------------------
class TestImap(MailTest):
    def test_real_bytes_sizes(self):
        self.assertEqual((len(SELECT_REPLY), len(FETCH_REPLY), len(BYE_REPLY)), (194, 325, 68))

    def test_curl_fetch_session(self):
        apps = replay(parse_imap, IMAP_CURL, IMAP_KEY)
        self.assertEqual([screen(a) for a in apps], IMAP_CURL_SCREEN)
        self.assertEqual({a.name for a in apps}, {"IMAP"})
        self.assertHidden("pass", apps)

    def test_fields(self):
        apps = replay(parse_imap, IMAP_CURL, IMAP_KEY)
        self.assertEqual(apps[3].fields["commands"], [{"tag": "A002", "command": "LOGIN", "arg": "user ****"}])
        self.assertEqual(apps[7].fields["commands"],
                         [{"tag": "A004", "command": "UID FETCH", "arg": "1 BODY[]"}])
        self.assertEqual(apps[6].fields["replies"][1], {"tag": "*", "status": None, "text": "3 EXISTS"})
        self.assertEqual(apps[6].fields["replies"][3],
                         {"tag": "*", "status": "OK", "text": "[UIDVALIDITY 1795324585] UIDs valid"})
        self.assertEqual(apps[8].fields["replies"][-1],
                         {"tag": "A004", "status": "OK", "text": "UID FETCH completed"})
        self.assertEqual(apps[8].fields["mails"][0]["size"], 262)
        self.assertEqual(apps[10].fields["replies"][0]["status"], "BYE")

    def test_curl_list_and_not_found(self):
        apps = replay(parse_imap, [(C, b'A003 LIST "" *\r\n'),
                                   (S, b'* LIST (\\HasNoChildren) "/" INBOX\r\nA003 OK LIST completed\r\n'),
                                   (C, b"A004 UID FETCH 9 BODY[]\r\n"), (S, b"A004 OK UID FETCH completed\r\n")],
                      IMAP_KEY)
        self.assertEqual([screen(a) for a in apps], [
            ['A003 LIST "" *'], ['* LIST (\\HasNoChildren) "/" INBOX', "A003 OK LIST completed"],
            ["A004 UID FETCH 9 BODY[]"], ["A004 OK UID FETCH completed"]])

    def test_fetch_split_everywhere(self):
        # 325 bytes를 어디서 둘로 잘라도 ({262} 표시 안, literal 안, literal 바로 뒤) 같은 결과
        for cut in range(1, len(FETCH_REPLY)):
            key = ("10.0.2.15", 54000 + cut, "192.168.0.10", 143)
            first = parse_imap(key, FETCH_REPLY[:cut], S)
            second = parse_imap(key, FETCH_REPLY[cut:], S)
            both = screen(first) + screen(second)
            for line in FETCH_SCREEN[1:]:
                self.assertEqual(both.count(line), 1, (cut, line))
            self.assertEqual(second.fields["replies"][-1]["status"], "OK", cut)
            self.assertEqual(screen(parse_imap(key, BYE_REPLY, S)), IMAP_CURL_SCREEN[10], cut)

    def test_literal_over_three_segments(self):
        body = b"".join(b"line %03d\r\n" % i for i in range(300))
        mail = b"From: a@test.local\r\nSubject: big\r\n\r\n" + body
        reply = b"* 2 FETCH (BODY[] {%d}\r\n" % len(mail) + mail + b")\r\nA005 OK FETCH completed\r\n"
        segments = [reply[i:i + 1448] for i in range(0, len(reply), 1448)]
        self.assertEqual(len(segments), 3)
        apps = [parse_imap(IMAP_KEY, seg, S) for seg in segments]
        head = len(b"* 2 FETCH (BODY[] {%d}\r\n" % len(mail))
        self.assertEqual(screen(apps[0]), [f"* 2 FETCH (BODY[] {{{len(mail)}}}", "  From: a@test.local",
                                           "  Subject: big",
                                           f"(메일이 다음 세그먼트로 이어짐: {1448 - head}/{len(mail)} bytes)"])
        self.assertEqual(screen(apps[1]), ["메일 내용 1448 bytes",
                                           f"(메일이 다음 세그먼트로 이어짐: {2896 - head}/{len(mail)} bytes)"])
        rest = len(mail) - (2896 - head)
        self.assertEqual(screen(apps[2]), [f"메일 내용 {rest} bytes",
                                           f"  메일 {len(mail)} bytes, body: {len(body)} bytes",
                                           ")", "A005 OK FETCH completed"])

    def test_other_literals(self):
        hdr = b"From: a@test.local\r\nSubject: hi\r\n\r\n"
        app = parse_imap(IMAP_KEY, b"* 1 FETCH (UID 1 BODY[HEADER.FIELDS (FROM SUBJECT)] {%d}\r\n" % len(hdr)
                         + hdr + b" BODY[TEXT] {12}\r\nhello world\n FLAGS (\\Seen))\r\n", S)
        self.assertEqual(screen(app), [
            f"* 1 FETCH (UID 1 BODY[HEADER.FIELDS (FROM SUBJECT)] {{{len(hdr)}}}", "  From: a@test.local",
            "  Subject: hi", f"  메일 헤더 {len(hdr)} bytes", "BODY[TEXT] {12}", "  literal 12 bytes",
            "FLAGS (\\Seen))"])
        empty = parse_imap(IMAP_KEY, b'* LIST () "/" {0}\r\n\r\nA9 OK done\r\n', S)  # 빈 literal 뒤 줄 끝
        self.assertEqual(screen(empty), ['* LIST () "/" {0}', "A9 OK done"])

    def test_append_waits_for_continuation(self):
        mail = b"From: a@test.local\r\nSubject: appended\r\n\r\nhi\r\n"
        apps = replay(parse_imap, [
            (C, b"A006 APPEND INBOX (\\Seen) {%d}\r\n" % len(mail)),
            (S, b"+ Ready for literal data\r\n"),                  # 동기 literal: "+"를 받은 뒤에 보낸다
            (C, mail),
            (C, b"\r\n"),                                          # imaplib는 literal 뒤 CRLF를 따로 보냄
            (S, b"A006 OK APPEND completed\r\n"),
            (C, b"A007 LOGOUT\r\n"),
        ], IMAP_KEY)
        self.assertEqual([screen(a) for a in apps], [
            [f"A006 APPEND INBOX (\\Seen) {{{len(mail)}}}"], ["+ Ready for literal data"],
            [f"메일 내용 {len(mail)} bytes", "  From: a@test.local", "  Subject: appended",
             f"  메일 {len(mail)} bytes, body: 4 bytes"],
            ["(줄 끝)"], ["A006 OK APPEND completed"], ["A007 LOGOUT"]])

    def test_append_rejected_before_literal(self):
        # 서버가 "+" 대신 NO → 클라이언트는 literal을 보내지 않고 다음 명령
        apps = replay(parse_imap, [(C, b"A006 APPEND Trash {310}\r\n"),
                                   (S, b"A006 NO [TRYCREATE] Mailbox does not exist (only INBOX)\r\n"),
                                   (C, b"A007 LOGOUT\r\n")], IMAP_KEY)
        self.assertEqual(apps[2].fields["commands"], [{"tag": "A007", "command": "LOGOUT", "arg": None}])

    def test_literal_plus(self):
        # {N+}: 기다리지 않고 바로 보냄 → 같은 세그먼트 안에서 이어 읽는다
        mail = b"Subject: plus\r\n\r\nx\r\n"
        app = parse_imap(IMAP_KEY, b"A008 APPEND INBOX {%d+}\r\n" % len(mail) + mail + b"\r\nA009 NOOP\r\n", C)
        self.assertEqual(screen(app), [f"A008 APPEND INBOX {{{len(mail)}+}}", "  Subject: plus",
                                       f"  메일 {len(mail)} bytes, body: 3 bytes", "A009 NOOP"])

    def test_secrets(self):
        apps = replay(parse_imap, [
            (C, b'A1 LOGIN "john doe" "p@ss word"\r\n'), (S, b"A1 NO bad\r\n"),
            (C, b"A2 LOGIN user {8}\r\n"), (S, b"+ Ready for literal data\r\n"),
            (C, b'p@ss"wd!\r\n'), (S, b"A2 NO bad\r\n"),               # 비밀번호 literal
            (C, b"A3 LOGIN {4}\r\n"), (S, b"+ Ready\r\n"),
            (C, b"user s3cr3t\r\n"), (S, b"A3 NO bad\r\n"),             # 사용자 이름 literal 뒤 비밀번호
            (C, b"A4 AUTHENTICATE PLAIN\r\n"), (S, b"+ \r\n"),
            (C, b"AHVzZXIAcGFzcw==\r\n"), (S, b"A4 NO AUTHENTICATE not supported, use LOGIN\r\n"),
            (C, b"A5 AUTHENTICATE PLAIN AHVzZXIAcGFzcw==\r\n"), (S, b"A5 NO no\r\n"),
            (C, b"A6 SELECT INBOX\r\n"),
        ], IMAP_KEY)
        self.assertEqual([a.summary for a in apps[0::2]], [
            'A1 LOGIN "john doe" ****', "A2 LOGIN user ****", SECRET, "A3 LOGIN {4}", "literal 4 bytes",
            "A4 AUTHENTICATE PLAIN", SECRET, "A5 AUTHENTICATE PLAIN ****", "A6 SELECT INBOX"])
        self.assertEqual(apps[8].lines, [SECRET])
        for secret in ("p@ss word", 'p@ss"wd!', "s3cr3t", "AHVzZXIAcGFzcw=="):
            self.assertHidden(secret, apps)


# -----------------------------------------------------------------------------
# STARTTLS 이후
# -----------------------------------------------------------------------------
class TestStartTls(MailTest):
    def test_smtp_accepted(self):
        apps = replay(parse_smtp, [
            (S, b"220 smtp.example.com ESMTP ready\r\n"),
            (C, b"EHLO client.example\r\n"),
            (S, b"250-smtp.example.com at your service\r\n250-SIZE 35882577\r\n250-STARTTLS\r\n250 SMTPUTF8\r\n"),
            (C, b"STARTTLS\r\n"),
            (S, b"220 2.0.0 Ready to start TLS\r\n"),
            (C, CLIENT_HELLO), (S, SERVER_HELLO), (C, APP_DATA), (S, b"250 looks like text\r\n"),
        ], SMTP_KEY)
        self.assertEqual(apps[4].summary, "220 2.0.0 Ready to start TLS")
        self.assertFalse(apps[4].fields["tls"])
        self.assertEqual([screen(a) for a in apps[5:]], [
            ["TLS (암호화 시작) 517 bytes"], ["TLS (암호화 시작) 127 bytes"], ["TLS (암호화 시작) 58 bytes"],
            ["TLS (암호화 시작) 21 bytes"]])                       # 이후는 글자처럼 보여도 해석하지 않음
        self.assertTrue(all(a.fields["tls"] for a in apps[5:]))
        self.assertEqual(apps[5].fields["commands"], [])

    def test_smtp_refused(self):
        # tools/mail_server.py는 STARTTLS를 거절 → 계속 평문
        apps = replay(parse_smtp, [(C, b"STARTTLS\r\n"), (S, b"454 TLS not available (plaintext test server)\r\n"),
                                   (C, b"QUIT\r\n")], SMTP_KEY)
        self.assertEqual(apps[2].summary, "QUIT")
        with self.assertRaises(ValueError):                    # 수락 전 TLS 바이트는 글자가 아님
            parse_smtp(SMTP_KEY, CLIENT_HELLO, C)

    def test_smtp_pipelined_reply_before_starttls(self):
        # 앞 명령의 응답(250)과 STARTTLS의 220을 보낸 순서로 짝짓는다
        apps = replay(parse_smtp, [(C, b"RSET\r\nSTARTTLS\r\n"),
                                   (S, b"250 OK\r\n220 Ready to start TLS\r\n"), (C, CLIENT_HELLO)], SMTP_KEY)
        self.assertEqual(apps[2].summary, "TLS (암호화 시작) 517 bytes")

    def test_greeting_220_is_not_tls(self):
        apps = replay(parse_smtp, [(S, b"220 mail.test.local ESMTP\r\n"), (C, b"EHLO x\r\n")], SMTP_KEY)
        self.assertEqual(apps[1].summary, "EHLO x")

    def test_pop3_stls(self):
        apps = replay(parse_pop3, [(C, b"STLS\r\n"), (S, b"-ERR TLS not available (plaintext test server)\r\n"),
                                   (C, b"STLS\r\n"), (S, b"+OK Begin TLS negotiation\r\n"),
                                   (C, CLIENT_HELLO), (S, SERVER_HELLO)], POP3_KEY)
        self.assertEqual([a.summary for a in apps], [
            "STLS", "-ERR TLS not available (plaintext test server)", "STLS", "+OK Begin TLS negotiation",
            "TLS (암호화 시작) 517 bytes", "TLS (암호화 시작) 127 bytes"])

    def test_imap_starttls(self):
        apps = replay(parse_imap, [(C, b"A001 STARTTLS\r\n"),
                                   (S, b"A001 BAD STARTTLS not available (plaintext test server)\r\n"),
                                   (C, b"A002 STARTTLS\r\n"), (S, b"* OK still plaintext\r\n"),
                                   (S, b"A002 OK Begin TLS negotiation now\r\n"),
                                   (C, CLIENT_HELLO), (S, SERVER_HELLO)], IMAP_KEY)
        self.assertEqual([a.summary for a in apps], [
            "A001 STARTTLS", "A001 BAD STARTTLS not available (plaintext test server)", "A002 STARTTLS",
            "* OK still plaintext", "A002 OK Begin TLS negotiation now",
            "TLS (암호화 시작) 517 bytes", "TLS (암호화 시작) 127 bytes"])

    def test_rest_of_segment_after_acceptance(self):
        replay(parse_smtp, [(C, b"STARTTLS\r\n")], SMTP_KEY)
        app = parse_smtp(SMTP_KEY, b"220 Go ahead\r\n" + SERVER_HELLO, S)
        self.assertEqual(screen(app), ["220 Go ahead", "TLS (암호화 시작) 127 bytes"])
        self.assertTrue(app.fields["tls"])

    def test_tls_is_per_connection(self):
        replay(parse_smtp, [(C, b"STARTTLS\r\n"), (S, b"220 Ready\r\n")], SMTP_KEY)
        other = ("10.0.2.15", 51999, "192.168.0.10", 25)
        self.assertEqual(parse_smtp(other, b"EHLO x\r\n", C).summary, "EHLO x")
        self.assertEqual(parse_smtp(SMTP_KEY, b"EHLO x\r\n", C).summary, "TLS (암호화 시작) 8 bytes")


# -----------------------------------------------------------------------------
# 줄 나누기·화면용 문자열·상태 (세 프로토콜 공통)
# -----------------------------------------------------------------------------
class TestLines(MailTest):
    def test_line_split_across_segments(self):
        first = parse_smtp(SMTP_KEY, b"MAIL FROM:<a@te", C)
        second = parse_smtp(SMTP_KEY, b"st.local>\r\nRCPT TO:<b@test.local>\r\n", C)
        self.assertEqual(screen(first), ["(줄이 다음 세그먼트로 이어짐: 이 세그먼트에 15 bytes)"])
        self.assertEqual(screen(second), ["MAIL FROM:<a@test.local>", "RCPT TO:<b@test.local>"])

    def test_split_password_is_hidden(self):
        first = parse_pop3(POP3_KEY, b"PASS s3c", C)
        second = parse_pop3(POP3_KEY, b"r3t\r\n", C)
        self.assertEqual(second.summary, "PASS ****")
        self.assertHidden("s3c", [first])
        self.assertHidden("r3t", [second])

    def test_imap_line_and_literal_marker_split(self):
        first = parse_imap(IMAP_KEY, b"* 3 EXI", S)
        second = parse_imap(IMAP_KEY, b"STS\r\n* 1 FETCH (BODY[TEXT] {1", S)
        third = parse_imap(IMAP_KEY, b"0}\r\n0123456789)\r\nA1 OK done\r\n", S)
        self.assertEqual(first.summary, "(줄이 다음 세그먼트로 이어짐: 이 세그먼트에 7 bytes)")
        self.assertEqual(screen(second), ["* 3 EXISTS", "(줄이 다음 세그먼트로 이어짐: 이 세그먼트에 24 bytes)"])
        self.assertEqual(screen(third), ["* 1 FETCH (BODY[TEXT] {10}", "  literal 10 bytes", ")", "A1 OK done"])

    def test_bare_lf_lines(self):
        app = parse_smtp(SMTP_KEY, b"250-a\n250 b\n", S)
        self.assertEqual(screen(app), ["250-a", "250 b"])

    def test_many_lines_are_capped(self):
        replay(parse_pop3, [(C, b"LIST\r\n")], POP3_KEY)
        listing = b"+OK 50 messages\r\n" + b"".join(b"%d 100\r\n" % i for i in range(1, 51)) + b".\r\n"
        app = parse_pop3(POP3_KEY, listing, S)
        self.assertEqual(len(app.lines), MAX_ITEMS)              # summary + 19줄 + "… 더"
        self.assertEqual(app.lines[-2:], ["  19 100", "… 32줄 더 (모두 52줄)"])
        self.assertEqual(parse_pop3(POP3_KEY, b"+OK Bye\r\n", S).summary, "+OK Bye")   # 상태는 끝까지 읽음

    def test_control_chars_are_safe_to_print(self):
        app = parse_smtp(SMTP_KEY, "250-ok\r\n250 \x1b[2J\u009b31m done\r\n".encode(), S)
        self.assertEqual(app.lines, ["250 \\x1b[2J\\x9b31m done"])
        long = parse_smtp(SMTP_KEY, b"250 " + b"x" * 300 + b"\r\n", S)
        self.assertEqual(len(long.summary), 201)
        self.assertTrue(long.summary.endswith("…"))

    def test_non_utf8_and_empty_line(self):
        self.assertEqual(parse_smtp(SMTP_KEY, b"250 caf\xe9\r\n", S).summary, "250 caf\ufffd")
        self.assertEqual(parse_smtp(SMTP_KEY, b"\r\n", C).summary, "(빈 줄)")

    def test_connections_are_separate(self):
        other = ("10.0.2.15", 51998, "192.168.0.10", 25)
        replay(parse_smtp, [(C, b"DATA\r\n"), (S, GO_AHEAD)], SMTP_KEY)
        self.assertEqual(parse_smtp(other, b"Subject: x\r\n", C).summary, "Subject: x")   # 명령 줄로
        self.assertEqual(parse_smtp(SMTP_KEY, b"Subject: x\r\n", C).summary, "메일 내용 12 bytes")
        # 같은 conn_key라도 프로토콜이 다르면 상태를 나누지 않음
        self.assertEqual(parse_imap(SMTP_KEY, b"A1 NOOP\r\n", C).summary, "A1 NOOP")

    def test_state_is_bounded(self):
        replay(parse_smtp, [(C, b"DATA\r\n"), (S, GO_AHEAD)], SMTP_KEY)
        for i in range(MAX_CONNS + 50):
            parse_smtp(("10.0.3.1", 40000 + i, "192.168.0.10", 25), b"NOOP\r\n", C)
        self.assertEqual(len(app_mail._conns), MAX_CONNS)
        # 가장 오래 안 쓴 연결(DATA 중이던 SMTP_KEY)은 잊음 → 이제 명령 줄로 읽는다
        self.assertEqual(parse_smtp(SMTP_KEY, b"Subject: x\r\n", C).summary, "Subject: x")

    def test_recently_used_is_kept(self):
        replay(parse_smtp, [(C, b"DATA\r\n"), (S, GO_AHEAD)], SMTP_KEY)
        for i in range(MAX_CONNS + 50):
            parse_smtp(("10.0.3.1", 40000 + i, "192.168.0.10", 25), b"NOOP\r\n", C)
            if i % 100 == 0:
                parse_smtp(SMTP_KEY, b"x\r\n", C)                  # 메일 내용을 계속 보내는 중
        self.assertEqual(parse_smtp(SMTP_KEY, b".\r\n", C).lines[-1], ".")


class TestBroken(MailTest):
    def test_empty_data(self):
        for parse in (parse_smtp, parse_pop3, parse_imap):
            for from_client in (C, S):
                with self.assertRaises(ValueError):
                    parse(SMTP_KEY, b"", from_client)

    def test_binary_first_line(self):
        cases = {
            "STARTTLS를 못 본 TLS ClientHello": CLIENT_HELLO,
            "NUL 바이트": b"\x00\x01\x02\x03",
            "줄 끝 없는 바이너리": b"\x16\x03",
            "첫 줄에 ESC (터미널 제어)": b"EHLO \x1b[31mred\r\n",
            "앞 세그먼트에서 이어진 줄에 제어 문자": b"\x7f\r\n",
        }
        for parse in (parse_smtp, parse_pop3, parse_imap):
            for why, data in cases.items():
                with self.assertRaises(ValueError, msg=f"{parse.__name__}: {why}"):
                    parse(SMTP_KEY, data, C)

    def test_error_does_not_change_state(self):
        parse_smtp(SMTP_KEY, b"MAIL FR", C)                       # 잘린 줄
        with self.assertRaises(ValueError):
            parse_smtp(SMTP_KEY, CLIENT_HELLO, C)
        self.assertEqual(parse_smtp(SMTP_KEY, b"OM:<a@x>\r\n", C).summary, "MAIL FROM:<a@x>")
        replay(parse_smtp, [(S, b"250 OK\r\n"), (C, b"STARTTLS\r\n")], SMTP_KEY)
        with self.assertRaises(ValueError):
            parse_smtp(SMTP_KEY, b"\x00garbage\r\n", S)
        self.assertEqual(parse_smtp(SMTP_KEY, b"220 Ready\r\n", S).summary, "220 Ready")   # 짝도 그대로
        self.assertEqual(parse_smtp(SMTP_KEY, CLIENT_HELLO, C).summary, "TLS (암호화 시작) 517 bytes")

    def test_binary_literal_is_fine(self):
        app = parse_imap(IMAP_KEY, b"* 1 FETCH (BINARY[1] ~{4}\r\n\x00\x01\x02\x03)\r\n", S)
        self.assertEqual(screen(app), ["* 1 FETCH (BINARY[1] ~{4}", "  literal 4 bytes", ")"])


# -----------------------------------------------------------------------------
# parse_app · decode → 화면 줄 (mock 없음)
# -----------------------------------------------------------------------------
class TestThroughParseApp(MailTest):
    def test_default_ports(self):
        key = ("10.0.2.15", 51000, "192.168.0.10", 25)
        for port, name, data in ((25, "SMTP", b"EHLO mail.txt\r\n"), (587, "SMTP", b"EHLO mail.txt\r\n"),
                                 (110, "POP3", b"USER user\r\n"), (143, "IMAP", b"A001 CAPABILITY\r\n")):
            app = parse_app(key, "TCP", 51000, port, data, DEFAULT_PORTS)
            self.assertEqual((app.name, app.summary, app.fields["from_client"]),
                             (name, data.decode().strip(), True))
            reply = parse_app(key, "TCP", port, 51000, b"+OK\r\n", DEFAULT_PORTS)
            self.assertEqual((reply.name, reply.fields["from_client"]), (name, False))

    def test_binary_is_value_error(self):
        # parse_app은 ValueError를 그대로 올리고, decode()가 잡아 [DATA]로 둔다
        with self.assertRaises(ValueError):
            parse_app(SMTP_KEY, "TCP", 51000, 25, CLIENT_HELLO, DEFAULT_PORTS)


class TestThroughDecode(MailTest):
    """프레임 → decode() → parse_app → parse_smtp/pop3/imap → format_packet 화면 줄."""

    def run_frames(self, segments, server_port, ports=DEFAULT_PORTS):
        from src import output              # A의 파일 — 깨져도 위쪽 테스트는 돌게 여기서 불러옴
        from src.decode import decode
        result = []
        for no, (from_client, data) in enumerate(segments, 1):
            if from_client:
                hdr, src, dst, direction = tcp_header(51000, server_port, 0x18), "10.0.2.15", "192.168.0.10", "OUT"
            else:
                hdr, src, dst, direction = tcp_header(server_port, 51000, 0x18), "192.168.0.10", "10.0.2.15", "IN"
            frame = eth(ipv4(hdr + data, src=src, dst=dst))
            with contextlib.redirect_stderr(io.StringIO()):
                pkt = decode(Captured(no=no, ts=1.0, direction=direction, frame=frame), ports)
            result.append((pkt, output.format_packet(pkt)))
        return result

    def test_smtp_data_lines(self):
        result = self.run_frames(SMTP_CURL, 25)
        self.assertTrue(all(pkt.app.name == "SMTP" for pkt, _ in result))
        lines = result[9][1]
        start = lines.index("  [SMTP] 메일 내용 177 bytes")
        self.assertEqual(lines[start + 1:], [
            "           From: a@test.local", "           To: b@test.local",
            "           Subject: wireshrimp SMTP test", "           Date: Mon, 23 Nov 2026 10:00:00 +0900",
            "           메일 172 bytes, body: 67 bytes", "         ."])
        self.assertIn("  [SMTP] EHLO mail.txt", result[1][1])

    def test_pop3_password_hidden_on_screen(self):
        result = self.run_frames(POP3_CURL, 110)
        self.assertIn("  [POP3] PASS ****", result[5][1])
        self.assertFalse(any("pass" in line for _pkt, lines in result for line in lines))

    def test_imap_fetch_lines(self):
        result = self.run_frames(IMAP_CURL, 143)
        self.assertIn("  [IMAP] A002 LOGIN user ****", result[3][1])
        lines = result[8][1]
        start = lines.index("  [IMAP] * 1 FETCH (UID 1 BODY[] {262}")
        self.assertEqual(lines[start + 1:], [
            "           From: wireshrimp <test@test.local>", "           To: user <user@test.local>",
            "           Subject: wireshrimp test mail", "           Date: Sun, 22 Nov 2026 12:00:00 +0900",
            "           메일 262 bytes, body: 98 bytes", "         )", "         A004 OK UID FETCH completed"])

    def test_no_sudo_ports(self):
        # 서버를 2525/2110/2143으로 띄우고 분석기에 --port smtp=2525,pop3=2110,imap=2143
        from tests.test_app_select import cli_ports
        ports = cli_ports("smtp=2525,pop3=2110,imap=2143")
        for segments, port, name in ((SMTP_CURL[:3], 2525, "SMTP"), (POP3_CURL[:3], 2110, "POP3"),
                                     (IMAP_CURL[:3], 2143, "IMAP")):
            app_mail.reset_state()
            result = self.run_frames(segments, port, ports)
            self.assertEqual([pkt.app.name for pkt, _ in result], [name] * 3)
            self.assertTrue(any(line.startswith(f"  [{name}] ") for line in result[1][1]))
        # 기본 포트 25는 이제 메일이 아님 → [DATA]
        (pkt, lines), = self.run_frames(SMTP_CURL[1:2], 25, ports)
        self.assertIsNone(pkt.app)
        self.assertTrue(any(line.startswith("  [DATA] 15 bytes") for line in lines), lines)

    def test_tls_after_starttls_and_binary_before(self):
        result = self.run_frames([(C, CLIENT_HELLO), (C, b"STARTTLS\r\n"), (S, b"220 Ready to start TLS\r\n"),
                                  (C, CLIENT_HELLO)], 587)
        self.assertIsNone(result[0][0].app)                     # STARTTLS 전 바이너리 → [DATA]
        self.assertTrue(any(line.startswith("  [DATA] 517 bytes") for line in result[0][1]))
        self.assertIn("  [SMTP] TLS (암호화 시작) 517 bytes", result[3][1])


if __name__ == "__main__":
    unittest.main()
