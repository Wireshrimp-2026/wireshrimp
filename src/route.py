# =============================================================================
# 담당자  : B
# 맡은 기능: traceroute 홉 표 (DESIGN 7.7)
#            - UDP 방식: 프로브(OUT, 목적지 포트 33434~33534) — IP TTL이 홉 번호
#              응답 ICMP 11/0(중간 라우터) · 3/3(도착)을 ICMP 안 원본 목적지 IP·포트로 프로브와 짝짓기
#            - ICMP 방식(traceroute -I): Echo Request(8)의 id·seq ↔ Echo Reply(0) 또는 Time Exceeded 안 원본 id·seq
#              TTL이 ECHO_PROBE_MAX_TTL보다 큰 Echo Request(ping — 리눅스 기본 TTL 64)는 프로브로 보지 않음
#            - RTT = ICMP 수신 시각 − 프로브 송신 시각, 무응답은 None
#            - 홉 표는 Time Exceeded가 아닌 응답(도착, Unreachable)을 처음 받은 홉까지
#              (traceroute는 여러 TTL을 한꺼번에 보내서, 도착한 홉보다 큰 TTL에도 목적지가 응답함)
#            - 한 홉에 응답한 라우터가 여럿이면(경로 부하 분산) 처음 응답한 라우터를 적는다
#            - 읽는 값: pkt.ip(ttl, src_ip, dst_ip), pkt.udp(dst_port), pkt.icmp, pkt.ts, pkt.direction
#            - add()는 traceroute와 상관없는 패킷에 예외를 내지 않는다 (main은 NotImplementedError만 잡음)
# 완료 기준: traceroute(UDP·ICMP 방식) 결과가 목적지별 홉 목록으로 나온다.
# =============================================================================
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .decode.icmp import DEST_UNREACHABLE, ECHO_REPLY, ECHO_REQUEST, TIME_EXCEEDED, describe
from .models import DIRECTION_IN, DIRECTION_OUT, TRACEROUTE_PORTS, Hop, PacketInfo

ECHO_PROBE_MAX_TTL = 63        # 이 TTL 이하의 Echo Request만 traceroute -I 프로브로 본다
PROTO_ICMP = 1
PROTO_UDP = 17


@dataclass
class _Reply:
    router: Optional[str]      # ICMP를 보낸 라우터 IP
    rtt_ms: float
    desc: str                  # 예: "11/0 Time Exceeded"
    final: bool                # Time Exceeded가 아님 = 경로 끝 (도착, Unreachable)


@dataclass
class _Probe:
    ttl: int                   # 홉 번호
    ts: float                  # 보낸 시각
    reply: Optional[_Reply] = None


class RouteTracker:
    """PacketInfo를 하나씩 받아 traceroute 프로브와 ICMP 응답을 짝짓는다."""

    def __init__(self) -> None:
        self._probes: dict[str, list[_Probe]] = {}     # 목적지 IP → 프로브 (보낸 순서)
        self._waiting: dict[tuple, _Probe] = {}         # 짝 맞출 열쇠 → 아직 응답 없는 프로브

    def add(self, pkt: PacketInfo) -> None:
        """프로브 또는 ICMP 응답이면 기록, 아니면 무시."""
        if not isinstance(pkt.ip, dict):
            return
        if pkt.direction == DIRECTION_OUT:
            key = _probe_key(pkt)
            ttl = pkt.ip.get("ttl")
            if key is None or not isinstance(ttl, int):
                return
            probe = _Probe(ttl=ttl, ts=pkt.ts)
            self._probes.setdefault(pkt.ip.get("dst_ip"), []).append(probe)
            self._waiting[key] = probe     # 같은 열쇠가 다시 오면(traceroute 다시 실행) 새 프로브와 짝
        elif pkt.direction == DIRECTION_IN and isinstance(pkt.icmp, dict):
            key = _reply_key(pkt)
            probe = self._waiting.pop(key, None) if key is not None else None
            if probe is None:              # 프로브 응답이 아니거나, 이미 응답을 받은 프로브
                return
            icmp_type, code = pkt.icmp.get("type"), pkt.icmp.get("code")
            probe.reply = _Reply(router=pkt.ip.get("src_ip"), rtt_ms=(pkt.ts - probe.ts) * 1000,
                                 desc=describe(icmp_type, code), final=icmp_type != TIME_EXCEEDED)

    def hops(self) -> dict[str, list[Hop]]:
        """{목적지 IP: [Hop, ...]} — 홉 번호 순. traceroute가 없었으면 빈 dict."""
        return {dst: _hop_table(probes) for dst, probes in self._probes.items()}


def _probe_key(pkt: PacketInfo) -> Optional[tuple]:
    """보낸 패킷이 traceroute 프로브면 응답과 짝 맞출 열쇠, 아니면 None."""
    dst = pkt.ip.get("dst_ip")
    if isinstance(pkt.udp, dict):
        port = pkt.udp.get("dst_port")
        lo, hi = TRACEROUTE_PORTS
        if isinstance(port, int) and lo <= port <= hi:
            return ("udp", dst, port)
    elif isinstance(pkt.icmp, dict) and pkt.icmp.get("type") == ECHO_REQUEST:
        if (pkt.ip.get("ttl") or 0) <= ECHO_PROBE_MAX_TTL:
            return ("icmp", dst, pkt.icmp.get("id"), pkt.icmp.get("seq"))
    return None


def _reply_key(pkt: PacketInfo) -> Optional[tuple]:
    """받은 ICMP가 프로브 응답일 수 있으면 그 프로브의 열쇠, 아니면 None."""
    icmp = pkt.icmp
    icmp_type = icmp.get("type")
    if icmp_type == ECHO_REPLY:                         # ICMP 방식 도착: 목적지가 보낸 Echo Reply
        return ("icmp", pkt.ip.get("src_ip"), icmp.get("id"), icmp.get("seq"))
    if icmp_type in (TIME_EXCEEDED, DEST_UNREACHABLE):  # 오류 메시지 안에 담긴 원본 = 프로브
        dst = icmp.get("orig_dst_ip")
        if icmp.get("orig_proto") == PROTO_UDP and icmp.get("orig_dst_port") is not None:
            return ("udp", dst, icmp["orig_dst_port"])
        if icmp.get("orig_proto") == PROTO_ICMP and icmp.get("orig_id") is not None:
            return ("icmp", dst, icmp["orig_id"], icmp.get("orig_seq"))
    return None


def _hop_table(probes: list[_Probe]) -> list[Hop]:
    """목적지 1곳의 프로브 → 홉 번호 순 [Hop]. 경로 끝 응답을 처음 받은 홉까지만."""
    by_ttl: dict[int, list[_Probe]] = {}
    for probe in probes:
        by_ttl.setdefault(probe.ttl, []).append(probe)
    ends = [ttl for ttl, group in by_ttl.items() if any(p.reply and p.reply.final for p in group)]
    last = min(ends) if ends else max(by_ttl)
    table: list[Hop] = []
    for ttl in sorted(t for t in by_ttl if t <= last):
        group = by_ttl[ttl]
        first = next((p.reply for p in group if p.reply), None)
        table.append((ttl, first.router if first else None,
                      [p.reply.rtt_ms if p.reply else None for p in group],
                      first.desc if first else None))
    return table
