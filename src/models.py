# =============================================================================
# 담당자  : A (수정은 팀 합의 — PR + 단톡방 공지 필수)
# 맡은 기능: 모듈 사이에서 주고받는 데이터 형식 정의 (docs/DESIGN.md 5장)
#            F1 → F2 : Captured
#            F2 → F3·F4 : PacketInfo (+ AppInfo)
#            F3 : Connection
#            traceroute : Hop
# 완료 기준: 두 사람이 이 파일의 형식만 보고 자기 모듈을 만들고 합칠 수 있다.
#            (알 수 없는 값은 0이 아니라 None)
# =============================================================================
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

DIRECTION_OUT = "OUT"
DIRECTION_IN = "IN"

# tcp["flags"] 문자열의 고정 순서 (Wireshark와 같음). 켜진 것만 쉼표로 잇는다. 예: "ACK,SYN"
TCP_FLAG_ORDER = ("CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN")

# --proto 로 고를 수 있는 이름 ("all"은 전부)
PROTOCOLS = ("http", "dns", "smtp", "pop3", "imap", "traceroute", "bittorrent", "tls")

# 응용 프로토콜 기본 포트 (DESIGN 3.1). --port smtp=2525 처럼 바꿀 수 있다.
# BitTorrent 피어·DHT는 포트가 정해져 있지 않아 내용으로 판별한다.
DEFAULT_PORTS: dict[str, tuple[int, ...]] = {
    "http": (80, 8080),
    "dns": (53,),
    "smtp": (25, 587),
    "pop3": (110,),
    "imap": (143,),
    "bittorrent": (6969,),          # 트래커 (HTTP)
    "tls": (443, 465, 993, 995),
}

# traceroute UDP 프로브 목적지 포트 범위 (이상, 이하)
TRACEROUTE_PORTS = (33434, 33534)

# (IP, 포트, IP, 포트)
ConnKey = tuple[str, int, str, int]
# (홉 번호, 라우터 IP 또는 None, [rtt ms 또는 None, ...], ICMP 설명 예: "11/0 Time Exceeded")
Hop = tuple[int, Optional[str], list[Optional[float]], Optional[str]]


def canonical_key(ip1: str, port1: int, ip2: str, port2: int) -> ConnKey:
    """방향과 상관없이 같은 연결이면 같은 키 (작은 쪽 끝점이 앞)."""
    a, b = (ip1, port1), (ip2, port2)
    if b < a:
        a, b = b, a
    return (a[0], a[1], b[0], b[1])


# -----------------------------------------------------------------------------
# 5.1 Captured — F1 → F2
# -----------------------------------------------------------------------------
@dataclass
class Captured:
    no: int           # 캡처 순번 (1부터)
    ts: float         # 커널 수신 시각 (초)
    direction: str    # "OUT" / "IN"
    frame: bytes      # 이더넷 헤더부터 프레임 전체


# -----------------------------------------------------------------------------
# 5.3 AppInfo — 응용 계층 공통 형식
# -----------------------------------------------------------------------------
@dataclass
class AppInfo:
    name: str                                         # "HTTP", "DNS", "SMTP", "POP3", "IMAP",
                                                      # "BT-TRACKER", "BT-PEER", "BT-DHT", "TLS"
    summary: str                                      # 한 줄 요약
    lines: list[str] = field(default_factory=list)    # 출력할 세부 줄 (그대로 찍힘)
    fields: dict = field(default_factory=dict)        # 다른 모듈이 쓸 값


# -----------------------------------------------------------------------------
# 5.2 PacketInfo — F2 → F3·F4
# -----------------------------------------------------------------------------
@dataclass
class PacketInfo:
    no: int
    ts: float
    direction: str                      # "OUT" / "IN"
    frame_len: int
    eth: dict                           # src_mac, dst_mac, ethertype, vlan
    ip: dict                            # version, header_len, tos, total_length, id, df, mf,
                                        # frag_offset, ttl, protocol, checksum, checksum_ok,
                                        # src_ip, dst_ip
    proto: str                          # "TCP" / "UDP" / "ICMP" / "OTHER"
    tcp: Optional[dict] = None          # src_port, dst_port, seq, ack, header_len, flags,
                                        # flag_bits, window, checksum, urgent, options
    udp: Optional[dict] = None          # src_port, dst_port, length, checksum,
                                        # checksum_ok (True / False / None=체크섬 안 씀)
    icmp: Optional[dict] = None         # type, code, type_name, checksum, (Echo) id, seq,
                                        # (오류) orig_src_ip, orig_dst_ip, orig_proto,
                                        # orig_src_port, orig_dst_port, orig_ttl
    payload: bytes = b""                # 전송 계층 헤더를 뗀 데이터
    app: Optional[AppInfo] = None       # 응용 계층 해석 결과
    rel_seq: Optional[int] = None       # F3에서 채움 (연결 시작 기준 상대값)
    rel_ack: Optional[int] = None

    @property
    def src_ip(self) -> str:
        return self.ip["src_ip"]

    @property
    def dst_ip(self) -> str:
        return self.ip["dst_ip"]

    @property
    def src_port(self) -> Optional[int]:
        l4 = self.tcp or self.udp
        return l4["src_port"] if l4 else None

    @property
    def dst_port(self) -> Optional[int]:
        l4 = self.tcp or self.udp
        return l4["dst_port"] if l4 else None


# -----------------------------------------------------------------------------
# 5.4 Connection — F3 (TCP 연결 1개)
# -----------------------------------------------------------------------------
@dataclass
class Connection:
    key: ConnKey                                       # (클라이언트 IP, 포트, 서버 IP, 포트)
    app_name: Optional[str] = None                     # 처음 판별된 응용 프로토콜
    isn_client: Optional[int] = None                   # 초기 Seq
    isn_server: Optional[int] = None
    handshake: list[PacketInfo] = field(default_factory=list)   # SYN, SYN/ACK, ACK
    data_count: dict = field(default_factory=lambda: {DIRECTION_OUT: 0, DIRECTION_IN: 0})
    data_bytes: dict = field(default_factory=lambda: {DIRECTION_OUT: 0, DIRECTION_IN: 0})
    retransmissions: int = 0
    teardown: list[PacketInfo] = field(default_factory=list)    # FIN 교환 + 마지막 ACK, 또는 RST
    state: str = "SYN_SENT"            # SYN_SENT → ESTABLISHED → FIN_WAIT → CLOSED / RESET
