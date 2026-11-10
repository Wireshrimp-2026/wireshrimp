# =============================================================================
# 담당자  : A (수정은 팀 합의 — PR + 단톡방 공지 필수)
# 맡은 기능: 모듈 사이에서 주고받는 데이터 형식 정의 (docs/DESIGN.md 2장)
#            F1 → F2 : Captured
#            F2 → F3 : PacketInfo (+ DnsInfo, HttpInfo)
#            F3 → F4 : Session
#            F4 → F5 : LatencyResult
# 완료 기준: 모든 팀원이 이 파일의 형식만 보고 자기 모듈을 만들고 합칠 수 있다.
#            (측정할 수 없는 값은 0이 아니라 None)
# =============================================================================
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# (내 IP, 내 포트, 서버 IP, 서버 포트)
ConnKey = tuple[str, int, str, int]
# (홉 번호, 라우터 IP 또는 None, 지연 ms 또는 None)
Hop = tuple[int, Optional[str], Optional[float]]

DIRECTION_OUT = "OUT"
DIRECTION_IN = "IN"

# tcp_flags 문자열의 고정 순서
TCP_FLAG_ORDER = ("SYN", "FIN", "RST", "PSH", "ACK")


# -----------------------------------------------------------------------------
# 2.1 Captured — F1 → F2
# -----------------------------------------------------------------------------
@dataclass
class Captured:
    ts: float         # 받은 시각 (초 단위, time.time())
    direction: str    # "OUT" (pkttype == PACKET_OUTGOING(4)) / "IN" (그 외)
    frame: bytes      # 이더넷 헤더부터 시작하는 프레임 전체


# -----------------------------------------------------------------------------
# 2.3 DnsInfo / HttpInfo — F2 내부 (C가 채움)
# -----------------------------------------------------------------------------
@dataclass
class DnsInfo:
    txid: int                 # Transaction ID
    is_response: bool         # QR 비트
    qname: str                # "neverssl.com"
    qtype: str                # "A", "AAAA", "CNAME" 등
    answers: list[tuple[str, int]] = field(default_factory=list)  # [(응답 IP, TTL)] — A 레코드만


@dataclass
class HttpInfo:
    is_request: bool
    # 요청일 때
    method: Optional[str] = None
    url: Optional[str] = None
    host: Optional[str] = None
    # 응답일 때
    status_code: Optional[int] = None    # 200
    reason: Optional[str] = None         # "OK"
    # 헤더에 있을 때
    content_length: Optional[int] = None


# -----------------------------------------------------------------------------
# 2.2 PacketInfo — F2 → F3 (설계안의 "패킷 정보 1건 형식")
# -----------------------------------------------------------------------------
@dataclass
class PacketInfo:
    # --- A: Captured / Ethernet / IP ---
    ts: float
    direction: str                        # "OUT" / "IN"
    src_mac: str                          # "aa:bb:cc:dd:ee:ff"
    dst_mac: str
    src_ip: str                           # "10.0.2.15"
    dst_ip: str
    ttl: int
    proto: str                            # "TCP" / "UDP" / "ICMP" / "OTHER"

    # --- B: TCP / UDP / ICMP ---
    src_port: Optional[int] = None        # TCP/UDP일 때만
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None       # "SYN", "SYN,ACK", "FIN,ACK" (순서: SYN,FIN,RST,PSH,ACK)
    seq: Optional[int] = None             # TCP일 때만
    ack: Optional[int] = None
    window: Optional[int] = None
    udp_length: Optional[int] = None      # UDP일 때만
    icmp_type: Optional[int] = None       # ICMP일 때만
    icmp_code: Optional[int] = None
    icmp_orig_dst_ip: Optional[str] = None    # ICMP 안 원본 IP 헤더의 목적지
    icmp_orig_dst_port: Optional[int] = None  # ICMP 안 원본 UDP 목적지 포트 (traceroute 짝)
    payload_len: int = 0                  # 전송 계층 헤더를 뗀 데이터 길이

    # --- C: DNS / HTTP ---
    dns: Optional[DnsInfo] = None         # 53번 포트일 때
    http: Optional[HttpInfo] = None       # 80번 포트이고 첫 줄·헤더가 있는 패킷일 때


# -----------------------------------------------------------------------------
# 2.4 Session — F3 → F4 (웹 접속 1회)
# -----------------------------------------------------------------------------
@dataclass
class Session:
    domain: str                                   # DNS 질의 도메인
    server_ip: str                                # DNS 응답 IP
    dns_query: Optional[PacketInfo] = None        # txid로 짝지은 질의
    dns_response: Optional[PacketInfo] = None     # txid로 짝지은 응답
    conn_key: Optional[ConnKey] = None            # (내 IP, 내 포트, 서버 IP, 서버 포트)
    syn: Optional[PacketInfo] = None              # 3-way handshake
    synack: Optional[PacketInfo] = None
    handshake_ack: Optional[PacketInfo] = None
    http_request: Optional[PacketInfo] = None     # 첫 GET
    http_first_response: Optional[PacketInfo] = None  # 데이터가 있는 첫 응답(IN)
    fin_packets: list[PacketInfo] = field(default_factory=list)  # FIN 교환 + 마지막 ACK
    # (traceroute UDP 프로브, 짝지은 ICMP 응답 또는 None)
    route_probes: list[tuple[PacketInfo, Optional[PacketInfo]]] = field(default_factory=list)
    packets: list[PacketInfo] = field(default_factory=list)      # 이 접속의 모든 패킷 (시간순)


# -----------------------------------------------------------------------------
# 2.5 LatencyResult — F4 → F5
# -----------------------------------------------------------------------------
@dataclass
class LatencyResult:
    domain: str
    server_ip: str
    dns_ms: Optional[float] = None               # 질의(OUT) → 응답(IN)
    tcp_connect_ms: Optional[float] = None       # SYN(OUT) → SYN+ACK(IN)
    http_first_byte_ms: Optional[float] = None   # GET(OUT) → 데이터 있는 첫 응답(IN)
    total_ms: Optional[float] = None             # DNS 질의 → 마지막 FIN/ACK
    hops: list[Hop] = field(default_factory=list)  # [(홉 번호, 라우터 IP, 지연 ms)] — 무응답은 None


# -----------------------------------------------------------------------------
# 2.6 CSV 형식 — F5 출력 칼럼 순서
# -----------------------------------------------------------------------------
CSV_COLUMNS = (
    "measured_at",          # 2026-11-20T14:03:11
    "dns_server",           # 실행 옵션 라벨 (예: google)
    "network",              # 실행 옵션 라벨 (예: school-wifi)
    "domain",
    "dns_ms",
    "tcp_connect_ms",
    "http_first_byte_ms",
    "total_ms",
    "hop_count",
    "hop_delays",           # "2.1;*;14.8;..." (세미콜론 구분, 무응답은 *)
)
