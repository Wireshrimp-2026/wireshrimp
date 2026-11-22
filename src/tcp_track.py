# =============================================================================
# 담당자  : A
# 맡은 기능: F3 TCP 연결 추적 (DESIGN 7.3)
#            - 연결설정: SYN → SYN,ACK → ACK. 양쪽 ISN 저장
#            - 데이터 전송: payload가 있는 세그먼트를 방향별로 개수·바이트 누적, 재전송(이미 받은 구간) 따로 셈
#              순서가 바뀌어 늦게 온 세그먼트(빈 구간을 채움)는 재전송이 아니다. keep-alive(1바이트)는 세지 않음
#            - 연결해제: FIN 교환 + 마지막 ACK (FIN,ACK가 겹쳐 3개로 끝나도 정상) / RST는 비정상 종료
#            - 상대 Seq/Ack: pkt.rel_seq = seq - ISN, pkt.rel_ack = ack - 상대 ISN
#            - 연결 이름: 처음 판별된 pkt.app.name
# 완료 기준: curl 1회가 연결 요약(Connection) 1개로 나온다 (연결설정 3개, 데이터, 연결해제).
#            상대 Seq/Ack가 PacketInfo에 채워진다.
# =============================================================================
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import ConnKey, Connection, PacketInfo, canonical_key

MOD = 1 << 32           # Seq/Ack는 32비트에서 한 바퀴 돈다

FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10

# 끝난 연결을 잠시 기억해 두는 개수. 마지막 ACK가 재전송되거나 뒤늦게 온 패킷이
# "캡처 전에 열린 새 연결"로 잘못 잡히지 않게 한다.
CLOSED_KEEP = 256


@dataclass
class _Side:
    """연결의 한쪽 끝(클라이언트 또는 서버) 상태."""
    base: Optional[int] = None        # 상대 Seq 기준값 (SYN이면 ISN, 아니면 처음 본 seq)
    max_end: int = 0                  # 지금까지 보낸 데이터의 끝 (상대값)
    ranges: list = field(default_factory=list)   # 받은 데이터 구간 [(시작, 끝), ...] 정렬·병합 — 재전송 판단
    fin_end: Optional[int] = None     # 보낸 FIN이 ACK 받으려면 필요한 상대 ack 값
    fin_acked: bool = False


@dataclass
class _Track:
    conn: Connection
    client: tuple[str, int]
    sides: dict[str, _Side] = field(default_factory=lambda: {"c": _Side(), "s": _Side()})


class TcpTracker:
    """PacketInfo를 하나씩 받아 TCP 연결 상태를 갱신한다."""

    def __init__(self) -> None:
        self._open: dict[ConnKey, _Track] = {}      # canonical_key → 진행 중 연결 (시작 순)
        self._closed: dict[ConnKey, _Track] = {}    # 방금 끝난 연결 (상대 Seq 계산용)

    def add(self, pkt: PacketInfo) -> Optional[Connection]:
        """TCP 패킷이면 상대 Seq/Ack를 채우고 연결 상태를 갱신.

        연결이 이 패킷으로 끝났으면(마지막 ACK 또는 RST) 그 Connection을, 아니면 None.
        같은 포트로 새 연결이 열려(새 SYN) 이전 연결이 밀려났으면 이전 Connection을 돌려준다.
        TCP가 아니면 아무것도 하지 않고 None.
        """
        tcp = pkt.tcp
        if pkt.proto != "TCP" or tcp is None:
            return None
        bits = tcp.get("flag_bits", 0)
        src = (pkt.src_ip, tcp["src_port"])
        dst = (pkt.dst_ip, tcp["dst_port"])
        key = canonical_key(src[0], src[1], dst[0], dst[1])

        is_syn = bool(bits & SYN) and not bits & ACK
        track = self._open.get(key)
        replaced: Optional[Connection] = None
        if (track is not None and bits & (SYN | ACK | RST | FIN) == SYN
                and _is_new_syn(track, src, tcp["seq"])):
            # 연결해제 마지막 ACK를 놓친 채 같은 포트로 다시 연결: 이전 연결을 끝내고 새로 시작
            replaced = self._finish(key)
            track = None
        if track is None:
            closed = self._closed.get(key)
            if closed is not None and not is_syn:
                # 이미 끝난 연결의 뒤늦은 패킷: 상대 Seq만 채우고 상태는 건드리지 않는다
                self._fill_relative(closed, pkt, src)
                return None
            self._closed.pop(key, None)
            track = self._new_track(pkt, src, dst, bits)
            self._open[key] = track

        conn = track.conn
        me, other = ("c", "s") if src == track.client else ("s", "c")
        side, peer = track.sides[me], track.sides[other]

        # --- 연결설정 ---
        if bits & SYN:
            side.base = tcp["seq"]
            if bits & ACK:                                       # SYN,ACK (서버)
                if conn.isn_server is None:
                    conn.isn_server = tcp["seq"]
                    conn.handshake.append(pkt)
                if conn.state == "SYN_SENT":
                    conn.state = "SYN_RCVD"
            elif conn.isn_client is None:                        # SYN (클라이언트), 재전송은 한 번만
                conn.isn_client = tcp["seq"]
                conn.handshake.append(pkt)
        elif side.base is None:
            side.base = tcp["seq"]                               # 캡처 전에 열린 연결

        self._fill_relative(track, pkt, src)

        if (conn.state == "SYN_RCVD" and me == "c" and bits & ACK and not bits & (SYN | FIN | RST)
                and pkt.rel_ack == 1):
            conn.handshake.append(pkt)
            conn.state = "ESTABLISHED"

        # --- 응용 이름 ---
        if conn.app_name is None and pkt.app is not None:
            conn.app_name = pkt.app.name

        # --- 데이터 전송 ---
        length = len(pkt.payload)
        if length and pkt.rel_seq is not None:
            start, end = pkt.rel_seq, pkt.rel_seq + length
            new = length - _overlap(side.ranges, start, end)
            if length == 1 and end == side.max_end:
                pass                                             # keep-alive: 데이터로 세지 않음
            elif new == 0:
                conn.retransmissions += 1
            else:
                conn.data_count[pkt.direction] += 1
                conn.data_bytes[pkt.direction] += new
                _add_range(side.ranges, start, end)
                side.max_end = max(side.max_end, end)

        # --- 비정상 종료 ---
        if bits & RST:
            conn.teardown.append(pkt)
            conn.state = "RESET"
            return self._finish(key)

        # --- 연결해제 ---
        in_teardown = False
        if (bits & ACK and peer.fin_end is not None and not peer.fin_acked
                and pkt.rel_ack is not None and pkt.rel_ack >= peer.fin_end):
            peer.fin_acked = True                                # 상대 FIN을 ACK
            in_teardown = True
        if bits & FIN and side.fin_end is None and pkt.rel_seq is not None:
            side.fin_end = pkt.rel_seq + length + 1              # FIN은 Seq 1을 쓴다
            conn.state = "FIN_WAIT"
            in_teardown = True                                   # FIN 재전송은 다시 넣지 않음
        if in_teardown:
            conn.teardown.append(pkt)

        sides = track.sides.values()
        if all(s.fin_end is not None and s.fin_acked for s in sides):
            conn.state = "CLOSED"
            return self._finish(key)
        return replaced           # 순수 SYN은 여기까지 온다 (위 두 return에는 걸리지 않음)

    def remaining(self) -> list[Connection]:
        """프로그램 종료 시 아직 끝나지 않은 연결 목록 (시작 순)."""
        return [t.conn for t in self._open.values()]

    # -------------------------------------------------------------------------
    def _new_track(self, pkt: PacketInfo, src: tuple[str, int], dst: tuple[str, int],
                   bits: int) -> _Track:
        """처음 보는 연결. 클라이언트(연결을 연 쪽)를 정한다."""
        if bits & SYN and not bits & ACK:
            client, server = src, dst                 # SYN 보낸 쪽
            state = "SYN_SENT"
        elif bits & SYN:
            client, server = dst, src                 # SYN,ACK를 받은 쪽 (SYN은 못 봄)
            state = "SYN_RCVD"
        else:
            # 캡처 전에 열린 연결: 포트가 큰 쪽(임시 포트)을 클라이언트로 본다
            client, server = (src, dst) if src[1] >= dst[1] else (dst, src)
            state = "ESTABLISHED"
        conn = Connection(key=(client[0], client[1], server[0], server[1]), state=state)
        track = _Track(conn=conn, client=client)
        if state == "SYN_RCVD":
            # SYN은 못 봤어도 SYN,ACK의 ack = 클라이언트 ISN + 1 → 클라이언트 기준값을 알 수 있다
            track.sides["c"].base = (pkt.tcp["ack"] - 1) % MOD
        return track

    @staticmethod
    def _fill_relative(track: _Track, pkt: PacketInfo, src: tuple[str, int]) -> None:
        me, other = ("c", "s") if src == track.client else ("s", "c")
        base, peer_base = track.sides[me].base, track.sides[other].base
        tcp = pkt.tcp
        pkt.rel_seq = (tcp["seq"] - base) % MOD if base is not None else None
        if tcp.get("flag_bits", 0) & ACK and peer_base is not None:
            pkt.rel_ack = (tcp["ack"] - peer_base) % MOD
        else:
            pkt.rel_ack = None

    def _finish(self, key: ConnKey) -> Connection:
        track = self._open.pop(key)
        self._closed[key] = track
        while len(self._closed) > CLOSED_KEEP:
            self._closed.pop(next(iter(self._closed)))
        return track.conn


def _is_new_syn(track: _Track, src: tuple[str, int], seq: int) -> bool:
    """열린 연결에 온 순수 SYN이 새 연결인지 (SYN 재전송은 ISN이 같다).

    클라이언트 ISN을 알면(SYN을 봤거나, SYN,ACK의 ack - 1) 그것과 비교하고,
    모르면(캡처 전에 열린 연결) 또는 반대쪽이 보낸 SYN이면 새 연결로 본다.
    """
    conn = track.conn
    if conn.isn_client is not None:
        known = conn.isn_client
    elif conn.isn_server is not None:
        known = track.sides["c"].base            # SYN,ACK부터 잡힌 연결
    else:
        known = None
    return src != track.client or known is None or seq != known


def _overlap(ranges: list, start: int, end: int) -> int:
    """[start, end) 중 이미 받은 구간과 겹치는 바이트 수."""
    return sum(max(0, min(end, e) - max(start, s)) for s, e in ranges)


def _add_range(ranges: list, start: int, end: int) -> None:
    """받은 구간을 추가하고, 붙거나 겹치는 구간을 하나로 합친다 (정렬 유지)."""
    ranges.append((start, end))
    ranges.sort()
    merged = [ranges[0]]
    for s, e in ranges[1:]:
        if s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))
    ranges[:] = merged
