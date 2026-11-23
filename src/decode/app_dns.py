# =============================================================================
# 담당자  : B
# 맡은 기능: DNS 해석 (DESIGN 7.4) — 필수
#            - 헤더: ID, Flags(QR, Opcode, AA, TC, RD, RA, Z, AD, CD, RCODE), QD/AN/NS/AR COUNT
#              (Z·AD·CD는 Wireshark처럼 1비트씩 — dig는 질의에 AD를 켠다)
#            - Question: 이름, Type, Class
#            - Answer/Authority/Additional: 이름, Type, Class, TTL, RDLENGTH,
#              RDATA (A, AAAA, CNAME, NS, MX, PTR, TXT, SOA, SRV, OPT(EDNS), 그 밖은 hex)
#            - 이름 압축 포인터(0xC0) 처리, 포인터 무한 반복 방지 (한 번 간 위치로 다시 가면 ValueError)
#            - over_tcp면 앞 2바이트 길이를 이 함수가 뗀다 (dig +tcp)
#            - summary는 Wireshark Info 칸과 같은 모양 (보고서 대조용): 질의 뒤에 Answer·Authority·Additional
#              레코드를 모두 붙인다 (dig가 붙이는 OPT 포함). 값은 Wireshark가 붙이는 타입만
#              (A, AAAA, NS, CNAME, PTR, DNAME, MX, SRV, SOA 주 서버, NSEC, HINFO, NAPTR, TLSA),
#              TXT·OPT·DS·HTTPS 등은 타입 이름만. 모르는 타입은 "Unknown (번호)"
#            - 이름·TXT의 출력할 수 없는 바이트는 dig처럼 \DDD로 바꾼다 (터미널 제어 문자 무력화)
# 완료 기준: DNS 헤더·플래그·질의·응답(A, AAAA, CNAME, MX)이 UDP·TCP 모두 AppInfo로 나온다.
# =============================================================================
from __future__ import annotations

import ipaddress
import struct
from typing import Optional

from ..models import AppInfo

HEADER_LEN = 12
MAX_NAME_LEN = 255            # 이름 최대 길이 (RFC 1035)
MAX_SUMMARY = 1000            # summary 최대 글자 수 (Wireshark처럼 레코드를 다 붙이되, 비정상적으로 긴 것만 자름)
MAX_SHOW = 200                # 세부 줄 최대 글자 수

TYPE_OPT = 41
# IANA DNS RR TYPE 이름 (Wireshark가 쓰는 이름과 같음, 255는 "ANY"). 여기 없으면 "Unknown (번호)"
TYPE_NAMES = {
    1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG", 9: "MR", 10: "NULL",
    11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO", 15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB",
    19: "X25", 20: "ISDN", 21: "RT", 22: "NSAP", 23: "NSAP-PTR", 24: "SIG", 25: "KEY", 26: "PX",
    27: "GPOS", 28: "AAAA", 29: "LOC", 30: "NXT", 31: "EID", 32: "NIMLOC", 33: "SRV", 34: "ATMA",
    35: "NAPTR", 36: "KX", 37: "CERT", 38: "A6", 39: "DNAME", 40: "SINK", 41: "OPT", 42: "APL",
    43: "DS", 44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID",
    50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP", 56: "NINFO", 57: "RKEY",
    58: "TALINK", 59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD",
    64: "SVCB", 65: "HTTPS", 99: "SPF", 100: "UINFO", 101: "UID", 102: "GID", 103: "UNSPEC",
    104: "NID", 105: "L32", 106: "L64", 107: "LP", 108: "EUI48", 109: "EUI64", 249: "TKEY",
    250: "TSIG", 251: "IXFR", 252: "AXFR", 253: "MAILB", 254: "MAILA", 255: "ANY", 256: "URI",
    257: "CAA", 258: "AVC", 259: "DOA", 260: "AMTRELAY", 32768: "TA", 32769: "DLV",
}
# Wireshark Info 칸에서 타입 이름 뒤에 세부 줄과 같은 값을 붙이는 타입: A NS CNAME PTR MX AAAA SRV DNAME
INFO_SAME_AS_DATA = (1, 2, 5, 12, 15, 28, 33, 39)
CLASS_NAMES = {1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}
OPCODE_NAMES = {0: "Standard query", 1: "Inverse query", 2: "Server status request",
                4: "Zone change notification", 5: "Dynamic update"}
RCODE_NAMES = {0: "No error", 1: "Format error", 2: "Server failure", 3: "No such name",
               4: "Not implemented", 5: "Refused"}
EDNS_OPTION_NAMES = {3: "NSID", 8: "ECS", 10: "COOKIE", 11: "KEEPALIVE", 12: "PADDING", 15: "EDE"}
SECTION_TAGS = ("AN", "NS", "AR")     # Answer, Authority, Additional


def parse_dns(data: bytes, over_tcp: bool = False) -> AppInfo:
    """DNS 메시지 → AppInfo(name="DNS"). 짧거나 깨졌으면 ValueError.

    summary 예: "Standard query 0x1a2b A neverssl.com"
               "Standard query response 0x1a2b A neverssl.com A 34.223.124.45"
    fields 키: txid, is_response, opcode, rcode, flags(dict), questions(list), answers(list),
              authority(list), additional(list)
              레코드 dict: name, type, type_name, class, ttl, rdlength, data(화면용 문자열),
                          info(summary에서 타입 이름 뒤에 붙는 값, 붙지 않는 타입이면 None)
    """
    msg = _strip_tcp_length(data) if over_tcp else data
    txid, flag_bits, qdcount, ancount, nscount, arcount = _unpack("!6H", msg, 0)
    flags = _flags(flag_bits)

    off = HEADER_LEN
    questions = []
    for _ in range(qdcount):
        name, off = read_name(msg, off)
        qtype, qclass = _unpack("!HH", msg, off)
        off += 4
        questions.append({"name": name, "type": qtype, "type_name": type_name(qtype),
                          "class": qclass})
    sections = []
    for count in (ancount, nscount, arcount):
        records = []
        for _ in range(count):
            record, off = _read_record(msg, off)
            records.append(record)
        sections.append(records)
    answers, authority, additional = sections

    lines = [
        f"id=0x{txid:04x} flags=0x{flag_bits:04x} " + " ".join(
            f"{k}={flags[k]}" for k in ("qr", "opcode", "aa", "tc", "rd", "ra", "z", "ad", "cd"))
        + f" rcode={flags['rcode']}({rcode_name(flags['rcode'])})",
        f"questions={qdcount} answers={ancount} authority={nscount} additional={arcount}",
    ]
    lines += [_clip(f"Q   {q['name']}  type={q['type_name']} class={class_name(q['class'])}")
              for q in questions]
    for tag, records in zip(SECTION_TAGS, sections):
        lines += [_clip(f"{tag:<3} {_record_line(r)}") for r in records]

    fields = {"txid": txid, "is_response": bool(flags["qr"]), "opcode": flags["opcode"],
              "rcode": flags["rcode"], "flags": flags, "questions": questions,
              "answers": answers, "authority": authority, "additional": additional}
    return AppInfo(name="DNS", summary=_clip(_summary(txid, flags, questions, sections), MAX_SUMMARY),
                   lines=lines, fields=fields)


# -----------------------------------------------------------------------------
# 이름 (압축 포인터)
# -----------------------------------------------------------------------------
def read_name(msg: bytes, off: int) -> tuple[str, int]:
    """off에서 이름을 읽는다 → (이름, 이름 다음 위치). 루트는 "<Root>" (Wireshark와 같음).

    압축 포인터(앞 2비트 11)를 따라가되, 한 번 간 위치로 다시 가면 무한 반복이므로 ValueError.
    """
    labels: list[str] = []
    after = None          # 처음 만난 포인터 다음 위치 = 이 이름이 끝나는 곳
    seen: set[int] = set()
    total = 0
    while True:
        if off >= len(msg):
            raise ValueError("DNS name truncated")
        length = msg[off]
        if length & 0xC0 == 0xC0:                         # 압축 포인터
            if off + 1 >= len(msg):
                raise ValueError("DNS compression pointer truncated")
            target = ((length & 0x3F) << 8) | msg[off + 1]
            if after is None:
                after = off + 2
            if target in seen:
                raise ValueError("DNS compression pointer loop")
            seen.add(target)
            off = target
            continue
        if length & 0xC0:
            raise ValueError(f"unsupported DNS label type 0x{length:02x}")
        off += 1
        if length == 0:
            break
        if off + length > len(msg):
            raise ValueError("DNS label truncated")
        total += length + 1
        if total > MAX_NAME_LEN:
            raise ValueError("DNS name too long")
        labels.append(_escape_label(msg[off:off + length]))
        off += length
    return (".".join(labels) or "<Root>"), (off if after is None else after)


# -----------------------------------------------------------------------------
# 레코드
# -----------------------------------------------------------------------------
def _read_record(msg: bytes, off: int) -> tuple[dict, int]:
    name, off = read_name(msg, off)
    rtype, rclass, ttl, rdlength = _unpack("!HHIH", msg, off)
    start = off + 10
    end = start + rdlength
    if end > len(msg):
        raise ValueError("DNS RDATA truncated")
    record = {"name": name, "type": rtype, "type_name": type_name(rtype), "class": rclass,
              "ttl": ttl, "rdlength": rdlength}
    if rtype == TYPE_OPT:
        record["data"] = _opt_text(rclass, ttl, msg[start:end])
    else:
        record["data"] = _rdata_text(rtype, msg, start, end)
    record["info"] = _info_text(record, msg, start, end)
    return record, end


def _rdata_text(rtype: int, msg: bytes, start: int, end: int) -> str:
    rdata = msg[start:end]
    if rtype == 1:                                            # A
        _need(rdata, 4, "A")
        return str(ipaddress.IPv4Address(rdata))
    if rtype == 28:                                           # AAAA
        _need(rdata, 16, "AAAA")
        return str(ipaddress.IPv6Address(rdata))
    if rtype in (2, 5, 12, 39):                               # NS, CNAME, PTR, DNAME
        return _name_in(msg, start, end)[0]
    if rtype == 15:                                           # MX
        (pref,) = _unpack("!H", msg[:end], start)
        return f"{pref} {_name_in(msg, start + 2, end)[0]}"
    if rtype == 6:                                            # SOA
        mname, off = _name_in(msg, start, end)
        rname, off = _name_in(msg, off, end)
        serial, refresh, retry, expire, minimum = _unpack("!5I", msg[:end], off)
        return (f"{mname} {rname} serial={serial} refresh={refresh} retry={retry} "
                f"expire={expire} minimum={minimum}")
    if rtype == 33:                                           # SRV
        prio, weight, port = _unpack("!HHH", msg[:end], start)
        return f"{prio} {weight} {port} {_name_in(msg, start + 6, end)[0]}"
    if rtype == 16:                                           # TXT: 길이 1바이트 + 문자열, 여러 개
        return " ".join(f'"{s}"' for s in _char_strings(rdata))
    return rdata.hex() if rdata else "(empty)"               # 그 밖의 타입은 hex


def _info_text(record: dict, msg: bytes, start: int, end: int) -> Optional[str]:
    """Wireshark Info 칸에서 타입 이름 뒤에 붙는 값. TXT·OPT·DS·HTTPS처럼 이름만 붙는 타입이면 None."""
    rtype = record["type"]
    if rtype in INFO_SAME_AS_DATA:
        return record["data"]
    if rtype == 6:                                            # SOA: 주 서버 이름만
        return record["data"].split(" ", 1)[0]
    try:                                                      # 아래는 세부 줄이 hex인 드문 타입
        if rtype == 47:                                       # NSEC: 다음 이름
            return _name_in(msg, start, end)[0]
        if rtype == 13:                                       # HINFO: CPU OS
            return " ".join(_char_strings(msg[start:end]))
        if rtype == 35:                                       # NAPTR: order preference flags
            order, pref, n = _unpack("!HHB", msg[:end], start)
            if start + 5 + n > end:
                raise ValueError("DNS NAPTR flags truncated")
            return f"{order} {pref} {_escape_text(msg[start + 5:start + 5 + n])}"
        if rtype == 52:                                       # TLSA: Wireshark는 소유자 이름을 붙인다
            return record["name"]
    except ValueError:
        return None                   # 깨진 드문 레코드는 타입 이름만 (메시지 전체를 버리지 않음)
    return None


def _char_strings(rdata: bytes) -> list[str]:
    """<character-string>(길이 1바이트 + 문자열) 여러 개 → 화면용 문자열 목록. 잘렸으면 ValueError."""
    parts, off = [], 0
    while off < len(rdata):
        n = rdata[off]
        if off + 1 + n > len(rdata):
            raise ValueError("DNS character-string truncated")
        parts.append(_escape_text(rdata[off + 1:off + 1 + n]))
        off += 1 + n
    return parts


def _name_in(msg: bytes, off: int, end: int) -> tuple[str, int]:
    """RDATA 안의 이름. 압축 포인터는 메시지 어디든 가리킬 수 있지만, 이름 자체는 RDATA를 넘으면 안 됨."""
    name, after = read_name(msg, off)
    if after > end:
        raise ValueError("DNS name runs past RDATA")
    return name, after


def _opt_text(udp_size: int, ttl: int, rdata: bytes) -> str:
    """EDNS OPT 레코드 (dig가 늘 붙임): Class 칸 = UDP 크기, TTL 칸 = 확장 RCODE·버전·DO 비트."""
    text = (f"udp_payload={udp_size} ext_rcode={ttl >> 24} version={(ttl >> 16) & 0xFF} "
            f"do={(ttl >> 15) & 1}")
    options, off = [], 0
    while off + 4 <= len(rdata):
        code, length = struct.unpack_from("!HH", rdata, off)
        options.append(f"{EDNS_OPTION_NAMES.get(code, f'OPT{code}')}({length}B)")
        off += 4 + length
    if off != len(rdata):
        raise ValueError("DNS EDNS option truncated")
    return text + (" options=" + ",".join(options) if options else "")


def _record_line(r: dict) -> str:
    if r["type"] == TYPE_OPT:
        return f"{r['name']}  type=OPT len={r['rdlength']}  {r['data']}"
    return (f"{r['name']}  type={r['type_name']} class={class_name(r['class'])} "
            f"ttl={r['ttl']} len={r['rdlength']}  {r['data']}")


# -----------------------------------------------------------------------------
# 헤더·요약
# -----------------------------------------------------------------------------
def _flags(bits: int) -> dict:
    return {"raw": bits, "qr": bits >> 15, "opcode": (bits >> 11) & 0xF, "aa": (bits >> 10) & 1,
            "tc": (bits >> 9) & 1, "rd": (bits >> 8) & 1, "ra": (bits >> 7) & 1,
            "z": (bits >> 6) & 1, "ad": (bits >> 5) & 1, "cd": (bits >> 4) & 1,
            "rcode": bits & 0xF}


def _summary(txid: int, flags: dict, questions: list, sections: list) -> str:
    """Wireshark Info 칸과 같은 모양. 질의 뒤에 Answer·Authority·Additional 레코드를 모두 붙인다.

    "Standard query 0x1a2b A neverssl.com OPT"
    "Standard query response 0x1a2b No such name A nx.example.com SOA a.iana-servers.net OPT"
    """
    op = OPCODE_NAMES.get(flags["opcode"], f"Unknown operation ({flags['opcode']})")
    parts = [op + (" response" if flags["qr"] else ""), f"0x{txid:04x}"]
    if flags["qr"] and flags["rcode"]:
        parts.append(rcode_name(flags["rcode"]))
    parts += [f"{q['type_name']} {q['name']}" for q in questions]
    for records in sections:
        parts += [r["type_name"] if r["info"] is None else f"{r['type_name']} {r['info']}"
                  for r in records]
    return " ".join(parts)


def _strip_tcp_length(data: bytes) -> bytes:
    """DNS over TCP: 앞 2바이트 = 메시지 길이. 메시지가 다음 세그먼트로 이어지면 ValueError."""
    (length,) = _unpack("!H", data, 0)
    msg = data[2:2 + length]
    if len(msg) < length:
        raise ValueError(f"DNS over TCP message continues: need {length}, got {len(msg)}")
    return msg


# -----------------------------------------------------------------------------
# 작은 도우미
# -----------------------------------------------------------------------------
def type_name(t: int) -> str:
    return TYPE_NAMES.get(t, f"Unknown ({t})")


def class_name(c: int) -> str:
    return CLASS_NAMES.get(c, f"CLASS{c}")


def rcode_name(r: int) -> str:
    return RCODE_NAMES.get(r, f"RCODE{r}")


def _unpack(fmt: str, buf: bytes, off: int) -> tuple:
    """struct.unpack_from인데, 모자라면 struct.error 대신 ValueError (파서 약속)."""
    if off + struct.calcsize(fmt) > len(buf):
        raise ValueError("DNS message truncated")
    return struct.unpack_from(fmt, buf, off)


def _need(rdata: bytes, size: int, what: str) -> None:
    if len(rdata) != size:
        raise ValueError(f"DNS {what} RDATA must be {size} bytes, got {len(rdata)}")


def _escape_label(raw: bytes) -> str:
    """이름 label: 출력할 수 있는 ASCII는 그대로, '.'·'\\'는 \\., \\\\, 나머지는 \\DDD (dig와 같음)."""
    out = []
    for b in raw:
        if b in (0x2E, 0x5C):
            out.append("\\" + chr(b))
        elif 0x21 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"\\{b:03d}")
    return "".join(out)


def _escape_text(raw: bytes) -> str:
    """TXT 문자열: 공백까지는 그대로, '"'·'\\'는 앞에 \\, 출력할 수 없는 바이트는 \\DDD."""
    out = []
    for b in raw:
        if b in (0x22, 0x5C):
            out.append("\\" + chr(b))
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"\\{b:03d}")
    return "".join(out)


def _clip(text: str, limit: int = MAX_SHOW) -> str:
    return text if len(text) <= limit else text[:limit] + "…"
