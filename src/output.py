# =============================================================================
# 담당자  : A
# 맡은 기능: F4 화면·로그 출력 (DESIGN 4장)
#            - 4.1 패킷별 출력: 번호·시각·방향·주소 한 줄 + [ETH] [IP] [TCP]/[UDP]/[ICMP] + 응용(app.lines)
#              응용을 판별 못 한 데이터는 [DATA] N bytes + 앞 32바이트 hex, hex=True면 원본 덤프
#              IP 체크섬: ok / bad, OUT이고 bad면 offload
#              UDP 체크섬: ok / bad, checksum_partial(offload 미완성 값)이면 offload, None이면 unused
#            - 4.2 TCP 연결 요약 (연결설정 / 데이터 / 연결해제, RST, 캡처 전에 열린 연결)
#            - 4.3 traceroute 홉 표
#            - open_log()가 불렸으면 화면과 같은 내용을 파일에도 쓴다
# 완료 기준: 4.1·4.2·4.3 형식이 모두 찍히고 로그 파일에도 같은 내용이 남는다.
# =============================================================================
from __future__ import annotations

import sys
import time
from typing import Optional, TextIO

from .models import DIRECTION_OUT, Connection, Hop, PacketInfo

INDENT = " " * 9          # "  [TCP ] " 뒤 이어지는 줄의 들여쓰기
DATA_PREVIEW = 32         # [DATA]에서 보여 줄 앞부분 바이트 수

ETHERTYPE_NAMES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6"}
IP_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

_log: Optional[TextIO] = None


# -----------------------------------------------------------------------------
# 로그 파일
# -----------------------------------------------------------------------------
def open_log(path: str) -> None:
    """이후 출력을 path 파일에도 기록한다. 열 수 없으면 OSError (main에서 안내)."""
    global _log
    close_log()
    _log = open(path, "w", encoding="utf-8", buffering=1)   # 줄 단위로 바로 기록


def close_log() -> None:
    """로그 파일을 닫는다 (열려 있지 않으면 아무것도 안 함)."""
    global _log
    if _log is not None:
        _log.close()
        _log = None


def _emit(lines: list[str]) -> None:
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    sys.stdout.flush()
    if _log is not None:
        _log.write(text)


# -----------------------------------------------------------------------------
# 4.1 패킷별 출력
# -----------------------------------------------------------------------------
def print_packet(pkt: PacketInfo, hex: bool = False) -> None:
    """패킷 1건을 4.1 형식으로 출력."""
    _emit(format_packet(pkt, hex=hex))


def format_packet(pkt: PacketInfo, hex: bool = False) -> list[str]:
    lines = [_title_line(pkt)]
    lines += _eth_lines(pkt)
    lines += _ip_lines(pkt)
    if pkt.tcp is not None:
        lines += _tcp_lines(pkt)
    elif pkt.udp is not None:
        lines += _udp_lines(pkt)
    elif pkt.icmp is not None:
        lines += _icmp_lines(pkt)

    if pkt.app is not None:
        lines.append(f"  [{pkt.app.name:<4}] {pkt.app.summary}")
        lines += [INDENT + line for line in pkt.app.lines]
    elif pkt.payload:
        preview = pkt.payload[:DATA_PREVIEW].hex(" ")
        more = " …" if len(pkt.payload) > DATA_PREVIEW else ""
        lines.append(f"  [DATA] {len(pkt.payload)} bytes  {preview}{more}")

    if hex and pkt.frame:
        lines += [INDENT + row for row in hexdump(pkt.frame)]
    return lines


def _title_line(pkt: PacketInfo) -> str:
    # 소수 연산 오차로 .049999처럼 찍히지 않게 마이크로초 정수로 반올림해서 나눈다
    sec, usec = divmod(int(round(pkt.ts * 1_000_000)), 1_000_000)
    t = time.strftime("%H:%M:%S", time.localtime(sec)) + f".{usec:06d}"
    if pkt.src_port is not None:
        addr = f"{pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port}"
    else:
        addr = f"{pkt.src_ip} -> {pkt.dst_ip}"
    return f"#{pkt.no:<4} {t}  {pkt.direction:<3}  {pkt.proto:<4} {addr}  len={pkt.frame_len}"


def _eth_lines(pkt: PacketInfo) -> list[str]:
    eth = pkt.eth
    etype = eth.get("ethertype", 0x0800)
    vlan = f" vlan={eth['vlan']}" if eth.get("vlan") is not None else ""
    return [f"  [ETH ] dst={eth['dst_mac']} src={eth['src_mac']} "
            f"type=0x{etype:04x}({ETHERTYPE_NAMES.get(etype, '?')}){vlan}"]


def _checksum_note(ok: Optional[bool], direction: str) -> str:
    """체크섬 검증 결과 표시. 보내는 패킷은 NIC가 나중에 채우므로(오프로드) 틀려 보일 수 있다."""
    if ok is None:
        return "unused"
    if ok:
        return "ok"
    return "offload" if direction == DIRECTION_OUT else "bad"


def _ip_lines(pkt: PacketInfo) -> list[str]:
    ip = pkt.ip
    flags = ",".join(name for name, on in (("DF", ip.get("df")), ("MF", ip.get("mf"))) if on) or "-"
    proto = ip.get("protocol")
    note = _checksum_note(ip.get("checksum_ok"), pkt.direction)
    return [
        f"  [IP  ] ver={ip.get('version')} hlen={ip.get('header_len')} tos=0x{ip.get('tos', 0):02x} "
        f"total={ip.get('total_length')} id=0x{ip.get('id', 0):04x} flags={flags} "
        f"frag={ip.get('frag_offset')} ttl={ip.get('ttl')} "
        f"proto={proto}({IP_PROTO_NAMES.get(proto, 'OTHER')}) cksum=0x{ip.get('checksum', 0):04x}({note})",
        f"{INDENT}src={ip['src_ip']} dst={ip['dst_ip']}",
    ]


def _tcp_lines(pkt: PacketInfo) -> list[str]:
    tcp = pkt.tcp
    if pkt.rel_seq is not None:
        rel_ack = pkt.rel_ack if pkt.rel_ack is not None else "-"
        seq = f"seq={pkt.rel_seq} ack={rel_ack} (raw seq={tcp['seq']} ack={tcp['ack']})"
    else:
        seq = f"seq={tcp['seq']} ack={tcp['ack']}"
    opts = f" opts=[{', '.join(tcp['options'])}]" if tcp.get("options") else ""
    return [
        f"  [TCP ] sport={tcp['src_port']} dport={tcp['dst_port']} {seq}",
        f"{INDENT}hlen={tcp.get('header_len')} flags={tcp.get('flags') or '-'} win={tcp.get('window')} "
        f"cksum=0x{tcp.get('checksum', 0):04x} urg={tcp.get('urgent')}{opts}",
    ]


def _udp_lines(pkt: PacketInfo) -> list[str]:
    udp = pkt.udp
    ok = udp.get("checksum_ok")
    if udp.get("checksum_partial"):
        note = "offload"                     # 의사 헤더 합만 들어 있음 → 랜카드가 채울 값
    elif ok is None:
        note = "unused" if udp.get("checksum") == 0 else "unchecked"
    else:
        note = "ok" if ok else "bad"         # UDP는 offload 값을 정확히 알아보므로 방향과 상관없음
    return [f"  [UDP ] sport={udp['src_port']} dport={udp['dst_port']} len={udp.get('length')} "
            f"cksum=0x{udp.get('checksum', 0):04x}({note})"]


def _icmp_lines(pkt: PacketInfo) -> list[str]:
    icmp = pkt.icmp
    name = f" {icmp['type_name']}" if icmp.get("type_name") else ""
    line = f"  [ICMP] type={icmp.get('type')} code={icmp.get('code')}{name}"
    if icmp.get("checksum") is not None:
        line += f" cksum=0x{icmp['checksum']:04x}"
    if icmp.get("id") is not None:
        line += f" id={icmp['id']} seq={icmp.get('seq')}"
    lines = [line]
    if icmp.get("orig_dst_ip") is not None:
        orig = (f"{INDENT}orig: {icmp.get('orig_src_ip')} -> {icmp['orig_dst_ip']} "
                f"proto={icmp.get('orig_proto')} ttl={icmp.get('orig_ttl')}")
        if icmp.get("orig_dst_port") is not None:
            orig += f" port {icmp.get('orig_src_port')} -> {icmp['orig_dst_port']}"
        lines.append(orig)
    return lines


def hexdump(data: bytes) -> list[str]:
    """Wireshark 아래 창처럼 16바이트씩: 오프셋, hex, ASCII."""
    rows = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{off:04x}  {hexpart:<47}  {text}")
    return rows


# -----------------------------------------------------------------------------
# 4.2 TCP 연결 요약
# -----------------------------------------------------------------------------
def print_connection(conn: Connection) -> None:
    """TCP 연결 1개를 4.2 형식으로 출력."""
    _emit(format_connection(conn))


def format_connection(conn: Connection) -> list[str]:
    c_ip, c_port, s_ip, s_port = conn.key
    lines = [f"[CONN] {c_ip}:{c_port} <-> {s_ip}:{s_port}  ({conn.app_name or 'TCP'})"]

    if not conn.handshake:
        lines.append("  연결설정  (캡처 전에 열림)")
    else:
        for i, pkt in enumerate(conn.handshake):
            note = "      (3-way handshake 완료)" if i == 2 else ""
            lines.append(("  연결설정  " if i == 0 else "            ") + _seg(pkt) + note)
        if len(conn.handshake) < 3 and conn.state in ("SYN_SENT", "SYN_RCVD"):
            lines.append("            (handshake 미완료)")

    out_n, in_n = conn.data_count.get("OUT", 0), conn.data_count.get("IN", 0)
    out_b, in_b = conn.data_bytes.get("OUT", 0), conn.data_bytes.get("IN", 0)
    data = f"  데이터    OUT {out_n}개 세그먼트 {out_b:,} bytes / IN {in_n}개 세그먼트 {in_b:,} bytes"
    if conn.retransmissions:
        data += f" (재전송 {conn.retransmissions}개)"
    lines.append(data)

    if not conn.teardown:
        lines.append("  연결해제  (캡처 종료까지 열려 있음)")
    else:
        last = len(conn.teardown) - 1
        for i, pkt in enumerate(conn.teardown):
            note = ""
            if i == last:
                note = {"CLOSED": "      (정상 종료)", "RESET": "      (RST, 비정상 종료)"}.get(
                    conn.state, "      (해제 진행 중에 캡처 종료)")
            lines.append(("  연결해제  " if i == 0 else "            ") + _seg(pkt) + note)
    return lines


def _seg(pkt: PacketInfo) -> str:
    """연결 요약의 세그먼트 한 줄: #번호 방향 플래그 seq ack"""
    tcp = pkt.tcp or {}
    seq = pkt.rel_seq if pkt.rel_seq is not None else tcp.get("seq")
    text = f"#{pkt.no:<4} {pkt.direction:<3} {tcp.get('flags') or '-':<8} seq={seq}"
    if pkt.rel_ack is not None:
        text += f" ack={pkt.rel_ack}"
    return text


# -----------------------------------------------------------------------------
# 4.3 traceroute 홉 표
# -----------------------------------------------------------------------------
def print_route(dst: str, hops: list[Hop]) -> None:
    """목적지 1곳의 traceroute 결과를 4.3 형식 홉 표로 출력."""
    _emit(format_route(dst, hops))


def format_route(dst: str, hops: list[Hop]) -> list[str]:
    width = max((len(rtts) for _n, _ip, rtts, _d in hops), default=3) or 3
    head = "  hop  router           " + "".join(f"rtt{i + 1:<6}" for i in range(width)) + "ICMP"
    lines = [f"[ROUTE] -> {dst}", head]
    for n, ip, rtts, desc in hops:
        cells = [f"{r:.1f} ms" if r is not None else "*" for r in rtts]
        cells += ["*"] * (width - len(cells))
        note = desc if ip is not None else (desc or "(응답 없음)")
        if ip is not None and ip == dst:
            note = f"{note} (도착)" if note else "(도착)"
        lines.append(f"  {n:>3}  {ip or '*':<16} " + "".join(f"{c:<9}" for c in cells) + (note or ""))
    return lines
