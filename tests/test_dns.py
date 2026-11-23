# =============================================================================
# DNS 해석(parse_dns) 단위 테스트 (#12)
# - dig가 보내는 모양 그대로의 질의·응답 hex로 확인 (EDNS OPT·COOKIE 포함)
# - 그 밖의 레코드는 아래 msg()로 만들어 확인
# =============================================================================
import struct
import unittest

from src.decode.app_dns import MAX_SUMMARY, parse_dns, read_name
from src.decode.app_select import parse_app
from src.models import DEFAULT_PORTS

# dig @8.8.8.8 neverssl.com A — 질의 (flags 0x0120 = RD·AD, EDNS UDP 1232 + COOKIE)
DIG_QUERY = bytes.fromhex(
    "1a2b 0120 0001 0000 0000 0001"
    "08 6e 65 76 65 72 73 73 6c 03 63 6f 6d 00 0001 0001"
    "00 0029 04d0 00000000 000c 000a 0008 a1b2c3d4e5f60718")

# 그 응답 (flags 0x8180, 답 A 34.223.124.45 TTL 60, 이름은 압축 포인터 0xc00c)
DIG_RESPONSE = bytes.fromhex(
    "1a2b 8180 0001 0001 0000 0001"
    "08 6e 65 76 65 72 73 73 6c 03 63 6f 6d 00 0001 0001"
    "c00c 0001 0001 0000003c 0004 22df7c2d"
    "00 0029 04d0 00000000 0000")


# -----------------------------------------------------------------------------
# 메시지 만들기 도우미
# -----------------------------------------------------------------------------
def name(n: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".") if p) + b"\x00"


def rr(owner, rtype, rdata, ttl=300, rclass=1):
    owner = owner if isinstance(owner, bytes) else name(owner)
    return owner + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def msg(txid=0x1234, flags=0x8180, questions=(), answers=(), authority=(), additional=()):
    head = struct.pack("!6H", txid, flags, len(questions), len(answers), len(authority),
                       len(additional))
    q = b"".join(name(n) + struct.pack("!HH", t, 1) for n, t in questions)
    return head + q + b"".join(answers) + b"".join(authority) + b"".join(additional)


class TestDigMessages(unittest.TestCase):
    def test_query(self):
        app = parse_dns(DIG_QUERY)
        self.assertEqual(app.name, "DNS")
        self.assertEqual(app.summary, "Standard query 0x1a2b A neverssl.com OPT")   # Wireshark Info와 같음
        f = app.fields
        self.assertEqual(f["txid"], 0x1a2b)
        self.assertFalse(f["is_response"])
        self.assertEqual((f["flags"]["rd"], f["flags"]["ad"], f["flags"]["qr"]), (1, 1, 0))
        self.assertEqual(f["questions"], [{"name": "neverssl.com", "type": 1, "type_name": "A",
                                           "class": 1}])
        opt = f["additional"][0]
        self.assertEqual((opt["name"], opt["type_name"], opt["class"]), ("<Root>", "OPT", 1232))
        self.assertEqual(opt["data"], "udp_payload=1232 ext_rcode=0 version=0 do=0 options=COOKIE(8B)")
        self.assertEqual(app.lines[0], "id=0x1a2b flags=0x0120 qr=0 opcode=0 aa=0 tc=0 rd=1 ra=0 "
                                       "z=0 ad=1 cd=0 rcode=0(No error)")
        self.assertEqual(app.lines[1], "questions=1 answers=0 authority=0 additional=1")
        self.assertEqual(app.lines[2], "Q   neverssl.com  type=A class=IN")
        self.assertTrue(app.lines[3].startswith("AR  <Root>  type=OPT len=12  udp_payload=1232"))

    def test_response(self):
        app = parse_dns(DIG_RESPONSE)
        self.assertEqual(app.summary, "Standard query response 0x1a2b A neverssl.com A 34.223.124.45 OPT")
        f = app.fields
        self.assertTrue(f["is_response"])
        self.assertEqual((f["flags"]["ra"], f["rcode"]), (1, 0))
        a = f["answers"][0]
        self.assertEqual((a["name"], a["type_name"], a["ttl"], a["rdlength"], a["data"]),
                         ("neverssl.com", "A", 60, 4, "34.223.124.45"))     # 압축 포인터로 이름 찾음
        self.assertIn("AN  neverssl.com  type=A class=IN ttl=60 len=4  34.223.124.45", app.lines)

    def test_over_tcp(self):
        tcp = struct.pack("!H", len(DIG_RESPONSE)) + DIG_RESPONSE
        self.assertEqual(parse_dns(tcp, over_tcp=True).summary, parse_dns(DIG_RESPONSE).summary)
        # 길이 뒤에 다른 데이터가 붙어 있어도 첫 메시지만 본다
        self.assertEqual(parse_dns(tcp + b"\x00\x05extra", over_tcp=True).fields["txid"], 0x1a2b)
        with self.assertRaises(ValueError):                # 메시지가 다음 세그먼트로 이어짐
            parse_dns(tcp[:-5], over_tcp=True)
        with self.assertRaises(ValueError):
            parse_dns(b"\x00", over_tcp=True)


class TestRecordTypes(unittest.TestCase):
    def test_cname_chain_and_aaaa(self):
        m = msg(questions=[("www.example.com", 28)], answers=[
            rr("www.example.com", 5, name("example.com")),
            rr("example.com", 28, bytes.fromhex("2606280002200001024812581ac81946")),
        ])
        app = parse_dns(m)
        self.assertEqual(app.summary, "Standard query response 0x1234 AAAA www.example.com "
                                      "CNAME example.com AAAA 2606:2800:220:1:248:1258:1ac8:1946")
        self.assertEqual(app.fields["answers"][0]["data"], "example.com")

    def test_mx_with_compression_into_question(self):
        # gmail.com MX 5 gmail-smtp-in.l.google.com — 답의 이름은 질의 이름(오프셋 12)을 가리킴
        m = msg(questions=[("gmail.com", 15)], answers=[
            rr(b"\xc0\x0c", 15, struct.pack("!H", 5) + name("gmail-smtp-in.l.google.com")),
            rr(b"\xc0\x0c", 15, struct.pack("!H", 10) + b"\x04alt1\xc0\x0c"),   # alt1.gmail.com
        ])
        app = parse_dns(m)
        self.assertEqual([r["data"] for r in app.fields["answers"]],
                         ["5 gmail-smtp-in.l.google.com", "10 alt1.gmail.com"])
        self.assertIn("MX 5 gmail-smtp-in.l.google.com", app.summary)

    def test_nxdomain_with_soa(self):
        soa = name("a.iana-servers.net") + name("noc.dns.icann.org") + struct.pack("!5I", 2026112201,
                                                                                   7200, 3600, 1209600, 3600)
        m = msg(flags=0x8183, questions=[("nx.example.com", 1)], authority=[rr("example.com", 6, soa)])
        app = parse_dns(m)
        self.assertEqual(app.fields["rcode"], 3)
        self.assertEqual(app.summary, "Standard query response 0x1234 No such name A nx.example.com "
                                      "SOA a.iana-servers.net")
        self.assertEqual(app.fields["authority"][0]["data"],
                         "a.iana-servers.net noc.dns.icann.org serial=2026112201 refresh=7200 "
                         "retry=3600 expire=1209600 minimum=3600")
        self.assertIn("rcode=3(No such name)", app.lines[0])
        self.assertTrue(app.lines[-1].startswith("NS  example.com  type=SOA"))

    def test_ns_ptr_txt_srv_and_unknown(self):
        m = msg(questions=[("example.com", 255)], answers=[
            rr("example.com", 2, name("a.iana-servers.net")),
            rr("45.124.223.34.in-addr.arpa", 12, name("neverssl.com")),
            rr("example.com", 16, b'\x0bv=spf1 -all\x08say "hi"'),
            rr("_sip._tcp.example.com", 33, struct.pack("!HHH", 10, 60, 5060) + name("sip.example.com")),
            rr("example.com", 4000, b"\xde\xad"),
        ])
        app = parse_dns(m)
        data = [r["data"] for r in app.fields["answers"]]
        self.assertEqual(data, ["a.iana-servers.net", "neverssl.com", '"v=spf1 -all" "say \\"hi\\""',
                                "10 60 5060 sip.example.com", "dead"])
        self.assertEqual(app.fields["answers"][4]["type_name"], "Unknown (4000)")   # Wireshark와 같은 이름
        # Wireshark Info: TXT·모르는 타입은 이름만, NS·PTR·SRV는 값까지
        self.assertEqual(app.summary, "Standard query response 0x1234 ANY example.com NS a.iana-servers.net "
                                      "PTR neverssl.com TXT SRV 10 60 5060 sip.example.com Unknown (4000)")

    def test_rare_types_in_summary_like_wireshark(self):
        # tshark 4.6.4 Info 칸과 대조한 모양
        m = msg(questions=[("example.com", 255)], answers=[
            rr("example.com", 39, name("example.net")),                                    # DNAME
            rr("example.com", 13, b"\x03CPU\x02OS"),                                       # HINFO
            rr("example.com", 35, struct.pack("!HH", 100, 10) + b"\x01U\x07E2U+sip\x00"
               + name("sip.example.com")),                                                 # NAPTR
            rr("example.com", 47, name("b.example.com") + b"\x00\x01\x40"),                # NSEC
            rr("_443._tcp.example.com", 52, b"\x03\x01\x01" + bytes(32)),                  # TLSA
            rr("example.com", 99, b"\x0bv=spf1 -all"),                                     # SPF
            rr("example.com", 257, b"\x00\x05issueletsencrypt.org"),                       # CAA
            rr("example.com", 65, b"\x00\x01\x00"),                                        # HTTPS
        ])
        app = parse_dns(m)
        self.assertEqual(app.summary, "Standard query response 0x1234 ANY example.com DNAME example.net "
                                      "HINFO CPU OS NAPTR 100 10 U NSEC b.example.com "
                                      "TLSA _443._tcp.example.com SPF CAA HTTPS")
        self.assertEqual(app.fields["answers"][0]["data"], "example.net")      # DNAME 세부 줄도 이름

    def test_broken_rare_record_keeps_message(self):
        # NAPTR flags 길이가 RDATA를 넘음 → summary에는 타입 이름만, 메시지는 그대로 해석
        m = msg(questions=[("example.com", 35)], answers=[rr("example.com", 35, struct.pack("!HHB", 1, 2, 9))])
        app = parse_dns(m)
        self.assertEqual(app.summary, "Standard query response 0x1234 NAPTR example.com NAPTR")
        self.assertIsNone(app.fields["answers"][0]["info"])

    def test_summary_lists_every_record_like_wireshark(self):
        answers = [rr("many.example.com", 1, bytes([10, 0, 0, i])) for i in range(6)]
        app = parse_dns(msg(questions=[("many.example.com", 1)], answers=answers))
        self.assertEqual(app.summary, "Standard query response 0x1234 A many.example.com "
                                      + " ".join(f"A 10.0.0.{i}" for i in range(6)))
        self.assertEqual(len(app.fields["answers"]), 6)

    def test_summary_includes_authority_and_additional(self):
        # 레퍼럴: Authority의 NS + Additional의 glue A·AAAA + OPT (tshark Info와 같음)
        m = msg(flags=0x8100, questions=[("www.example.com", 1)],
                authority=[rr("example.com", 2, name("a.iana-servers.net")),
                           rr("example.com", 2, name("b.iana-servers.net"))],
                additional=[rr("a.iana-servers.net", 1, bytes([199, 43, 135, 53])),
                            rr("a.iana-servers.net", 28, bytes(15) + b"\x53"),
                            b"\x00" + struct.pack("!HHIH", 41, 512, 0, 0)])
        self.assertEqual(parse_dns(m).summary,
                         "Standard query response 0x1234 A www.example.com NS a.iana-servers.net "
                         "NS b.iana-servers.net A 199.43.135.53 AAAA ::53 OPT")

    def test_very_long_summary_is_clipped(self):
        answers = [rr("many.example.com", 1, bytes([10, 0, i // 256, i % 256])) for i in range(200)]
        app = parse_dns(msg(questions=[("many.example.com", 1)], answers=answers))
        self.assertEqual(len(app.summary), MAX_SUMMARY + 1)
        self.assertTrue(app.summary.endswith("…"))
        self.assertEqual(len(app.fields["answers"]), 200)        # fields에는 전부


class TestNames(unittest.TestCase):
    def test_root_and_escaping(self):
        self.assertEqual(read_name(b"\x00", 0), ("<Root>", 1))
        weird = b"\x05a.b c\x04\x1b[2J\x00"                       # label 안의 '.', 공백, ESC
        self.assertEqual(read_name(weird, 0)[0], "a\\.b\\032c.\\027[2J")

    def test_pointer_returns_position_after_pointer(self):
        data = name("example.com") + b"\x03www\xc0\x00"
        self.assertEqual(read_name(data, 13), ("www.example.com", len(data)))

    def test_broken_names_raise_value_error(self):
        cases = {
            "자기 자신을 가리킴": b"\xc0\x00",
            "서로 가리킴": b"\xc0\x02\xc0\x00",
            "범위 밖 포인터": b"\xc0\x50",
            "포인터 반쪽": b"\xc0",
            "label 잘림": b"\x05ab",
            "끝 0 없음": b"\x02ab",
            "확장 label 형식": b"\x41abc\x00",
            "255자 초과": (b"\x3f" + b"a" * 63) * 4 + b"\x00",
        }
        for why, data in cases.items():
            with self.assertRaises(ValueError, msg=why):
                read_name(data, 0)


class TestBrokenMessages(unittest.TestCase):
    def test_value_errors(self):
        good = DIG_RESPONSE
        cases = {
            "헤더 12바이트 미만": good[:11],
            "질의가 잘림": good[:30],
            "레코드가 잘림": good[:50],
            "RDLENGTH가 메시지보다 김": msg(answers=[rr("a.com", 1, b"\x01\x02\x03\x04")])[:-1],
            "A가 4바이트가 아님": msg(answers=[rr("a.com", 1, b"\x01\x02\x03")]),
            "AAAA가 16바이트가 아님": msg(answers=[rr("a.com", 28, b"\x00" * 4)]),
            "TXT 문자열 잘림": msg(answers=[rr("a.com", 16, b"\x09short")]),
            "CNAME 이름이 RDATA를 넘음": msg(answers=[rr("a.com", 5, b"\x03abc")]) + b"\x00",
            "질의 수만 크게": struct.pack("!6H", 1, 0x0100, 50, 0, 0, 0) + name("a.com") + b"\x00\x01\x00\x01",
            "압축 포인터 반복": struct.pack("!6H", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01",
        }
        for why, data in cases.items():
            with self.assertRaises(ValueError, msg=why):
                parse_dns(data)

    def test_lines_are_printable_strings(self):
        app = parse_dns(DIG_QUERY)
        self.assertTrue(all(isinstance(line, str) for line in app.lines))


class TestThroughParseApp(unittest.TestCase):
    """parse_app → parse_dns 실제 연결 (mock 없음)."""

    def test_udp_and_tcp(self):
        key = ("10.0.2.15", 40000, "8.8.8.8", 53)
        udp = parse_app(key, "UDP", 40000, 53, DIG_QUERY, DEFAULT_PORTS)
        self.assertEqual(udp.summary, "Standard query 0x1a2b A neverssl.com OPT")
        tcp = parse_app(key, "TCP", 53, 40000, struct.pack("!H", len(DIG_RESPONSE)) + DIG_RESPONSE,
                        DEFAULT_PORTS)
        self.assertEqual(tcp.fields["answers"][0]["data"], "34.223.124.45")

    def test_broken_dns_is_value_error(self):
        # parse_app은 ValueError를 그대로 올리고, decode()가 잡아 [DATA]로 둔다
        with self.assertRaises(ValueError):
            parse_app(("a", 1, "b", 53), "UDP", 40000, 53, b"\x00\x01", DEFAULT_PORTS)


if __name__ == "__main__":
    unittest.main()
