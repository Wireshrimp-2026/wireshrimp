# =============================================================================
# 담당자  : A
# 맡은 기능: F1 캡처
#            - AF_PACKET raw socket (root). protocol 0으로 만든 뒤 bind((iface, ETH_P_ALL))로
#              filter.iface 인터페이스 하나에서만 모든 프레임 수신
#              (tailscale0 같은 tun 장치는 이더넷 헤더가 없어 parse_ethernet이 깨짐, lo는 패킷이 두 번 보임)
#            - recvfrom() 주소 정보의 pkttype == PACKET_OUTGOING(4) → "OUT", 그 외 → "IN"
#            - 받은 시각: 커널 수신 시각(SIOCGSTAMP), 실패하면 time.time()
#            - 대상 서버 IP, 포트(53, 80), ICMP, traceroute 포트만 남기는 필터
#            - 종료 시 커널이 버린 프레임 수 경고 (PACKET_STATISTICS)
# 완료 기준: sudo 실행 시 curl http://neverssl.com 트래픽이 OUT/IN 구분되어
#            PacketInfo로 나온다. IP·TTL이 Wireshark와 일치한다.
#            실험 스크립트로 조건별 반복 실행 시 CSV가 쌓인다.
# =============================================================================
from __future__ import annotations

import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Iterator, Optional

from .models import DIRECTION_IN, DIRECTION_OUT, Captured

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
SIOCGSTAMP = 0x8906          # 커널이 프레임을 받은 시각 (struct timeval)
SOL_PACKET = 263
PACKET_STATISTICS = 6        # (받은 수, 버린 수) — 버퍼가 넘쳐 놓친 프레임 확인
# 한 프레임 최대 크기. TSO/GRO가 켜져 있으면 커널이 여러 세그먼트를 합친 큰 프레임을
# 넘겨주므로(IP 최대 65535 + 이더넷 14 > 65535) 넉넉히 잡는다. (tcpdump 기본 snaplen과 같음)
RECV_BUF = 262144
SOCK_RCVBUF = 4 * 1024 * 1024   # 순간적으로 몰려도 커널에서 버리지 않게

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_VLAN = 0x8100
_PROTO_ICMP, _PROTO_TCP, _PROTO_UDP = 1, 6, 17


@dataclass
class CaptureFilter:
    """캡처할 트래픽 조건."""
    iface: str = ""                                       # 캡처할 인터페이스 (예: wlo1, enp0s3) — ip -br link로 확인
    server_ips: list[str] = field(default_factory=list)   # 대상 서버 IP 목록 (비어 있으면 IP로 거르지 않음)
    ports: tuple[int, ...] = (53, 80)                      # 남길 TCP/UDP 포트
    allow_icmp: bool = True                                # ICMP 허용 여부
    traceroute_ports: tuple[int, int] = (33434, 33534)     # traceroute UDP 프로브 포트 범위 (이상, 이하)


def capture(filter: CaptureFilter) -> Iterator[Captured]:
    """필터에 맞는 프레임을 받을 때마다 Captured를 하나씩 내보내는 제너레이터.

    PermissionError(sudo 아님), OSError(없는 인터페이스)는 그대로 올려 main에서 안내한다.
    Ctrl+C(KeyboardInterrupt)도 그대로 올라가며, 소켓은 finally에서 닫힌다.
    """
    if filter.iface:
        # protocol 0으로 만들면 아직 아무 프레임도 받지 않는다. bind()에서 인터페이스와
        # ETH_P_ALL을 함께 지정해야, bind 전 잠깐 사이에 다른 인터페이스(lo, tailscale0,
        # docker0 …)의 프레임이 큐에 섞여 들어오는 것을 막을 수 있다. (tcpdump와 같은 방식)
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    else:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        _set_rcvbuf(sock)
        if filter.iface:
            sock.bind((filter.iface, ETH_P_ALL))   # 파이썬이 protocol을 htons 해 준다
        # 커널 시각 기록은 SIOCGSTAMP를 처음 부를 때 켜진다. 그 전에 받은 프레임은 시각이 없어
        # 'ioctl을 부른 순간'이 대신 돌아오므로, 첫 패킷이 오기 전에 미리 한 번 불러 켜 둔다.
        _kernel_timestamp(sock)

        server_ips = {socket.inet_aton(ip) for ip in filter.server_ips}
        while True:
            frame, addr = sock.recvfrom(RECV_BUF)
            if filter.iface and addr[0] != filter.iface:
                continue   # 만일을 위한 이중 확인
            if not frame_matches(frame, filter, server_ips):
                continue
            # 시각은 커널이 기록해 둔 값이라 필터를 먼저 돌려도 정확도가 떨어지지 않는다.
            # (버릴 프레임에 ioctl 시스템 호출을 낭비하지 않으려고 필터 뒤에 둠)
            ts = _kernel_timestamp(sock) or time.time()
            # addr = (ifname, proto, pkttype, hatype, hwaddr)
            direction = DIRECTION_OUT if addr[2] == PACKET_OUTGOING else DIRECTION_IN
            yield Captured(ts=ts, direction=direction, frame=frame)
    finally:
        _report_drops(sock)
        sock.close()


def _set_rcvbuf(sock: socket.socket) -> None:
    """커널 수신 버퍼를 키운다.

    SO_RCVBUF는 net.core.rmem_max(Ubuntu 기본 약 208KB)를 넘지 못하고 조용히 깎인다.
    root는 SO_RCVBUFFORCE로 한도를 넘길 수 있으므로 그것부터 시도한다.
    """
    for opt in (getattr(socket, "SO_RCVBUFFORCE", 33), socket.SO_RCVBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, SOCK_RCVBUF)
            return
        except OSError:
            continue


def _report_drops(sock: socket.socket) -> None:
    """캡처를 마칠 때 커널이 버퍼가 넘쳐 버린 프레임 수를 알린다 (실험 결과 신뢰도 확인용).

    PACKET_STATISTICS는 읽을 때마다 0으로 초기화되므로 이 함수는 한 번만 부른다.
    """
    try:
        raw = sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
        received, dropped = struct.unpack("II", raw)
    except (OSError, struct.error):
        return
    if dropped:
        print(f"[capture] 경고: 커널에서 버린 프레임 {dropped}개 (받은 {received}개) — "
              f"이 회차 결과는 빠진 패킷이 있을 수 있습니다", file=sys.stderr)


def _kernel_timestamp(sock: socket.socket) -> Optional[float]:
    """마지막으로 받은 프레임의 커널 수신 시각. 실패하면 None (→ time.time() 사용).

    recvfrom()이 돌아온 뒤 time.time()을 찍으면 파이썬 처리 지연이 섞이므로,
    지연(ms) 측정 정확도를 위해 커널 시각을 우선 사용한다.
    """
    try:
        import fcntl
        raw = fcntl.ioctl(sock.fileno(), SIOCGSTAMP, b"\0" * 16)
        sec, usec = struct.unpack("qq", raw)
        return sec + usec / 1_000_000
    except (OSError, ImportError, struct.error):
        return None


def frame_matches(frame: bytes, filter: CaptureFilter,
                  server_ips: Optional[set[bytes]] = None) -> bool:
    """decode() 전에 바이트 오프셋만 보고 빠르게 거르는 필터.

    남기는 것:
      - ICMP (allow_icmp일 때)                         → traceroute 응답
      - UDP 목적지 포트가 traceroute 범위 안           → traceroute 프로브
      - TCP/UDP 포트가 ports 안
          · 53(DNS)은 서버 IP와 상관없이 항상 남김 (DNS 서버 ≠ 대상 서버)
          · 그 밖의 포트는 server_ips가 있으면 상대 IP가 목록에 있을 때만
    IPv4가 아니거나 너무 짧으면 버린다 (decode도 어차피 None을 돌려줌).
    """
    if server_ips is None:
        server_ips = {socket.inet_aton(ip) for ip in filter.server_ips}

    if len(frame) < 14:
        return False
    off = 12
    ethertype = struct.unpack_from("!H", frame, off)[0]
    off += 2
    if ethertype == _ETHERTYPE_VLAN:
        if len(frame) < off + 4:
            return False
        ethertype = struct.unpack_from("!H", frame, off + 2)[0]
        off += 4
    if ethertype != _ETHERTYPE_IPV4 or len(frame) < off + 20:
        return False

    ihl = (frame[off] & 0x0F) * 4
    proto = frame[off + 9]
    frag_offset = struct.unpack_from("!H", frame, off + 6)[0] & 0x1FFF
    src_ip = frame[off + 12:off + 16]
    dst_ip = frame[off + 16:off + 20]

    if proto == _PROTO_ICMP:
        return filter.allow_icmp
    if proto not in (_PROTO_TCP, _PROTO_UDP):
        return False
    if frag_offset != 0:
        # 두 번째 이후 조각에는 포트가 없다 → 서버 IP로만 판단
        return bool(server_ips) and (src_ip in server_ips or dst_ip in server_ips)

    l4 = off + ihl
    if len(frame) < l4 + 4:
        return False
    sport, dport = struct.unpack_from("!HH", frame, l4)

    lo, hi = filter.traceroute_ports
    if proto == _PROTO_UDP and lo <= dport <= hi:
        return True
    if sport not in filter.ports and dport not in filter.ports:
        return False
    if 53 in (sport, dport):
        return True
    if not server_ips:
        return True
    return src_ip in server_ips or dst_ip in server_ips
