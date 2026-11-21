# =============================================================================
# 담당자  : A (수정은 PR + 다른 한 명 확인)
# 맡은 기능: 실행 시작점 — 옵션 처리, 캡처 → 해석 → 연결 추적·traceroute → 출력·저장 전체 연결
#            sudo python3 -m src.main --iface enp0s3 --proto http,dns --log results/http.txt \
#                 --pcap results/http.pcap
# 완료 기준: 옵션대로 캡처·출력·로그·pcap 저장이 되고, 종료 시 남은 연결 요약과 홉 표가 찍힌다.
#            아직 구현되지 않은 모듈이 있어도 나머지는 돈다.
# =============================================================================
from __future__ import annotations

import argparse
import errno
import ipaddress
import signal
import sys

from . import output
from .capture import CaptureFilter, capture
from .decode import decode
from .models import DEFAULT_PORTS, PROTOCOLS, PacketInfo
from .pcap import PcapWriter
from .route import RouteTracker
from .tcp_track import TcpTracker


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python3 -m src.main",
        description="Raw Socket 기반 패킷 캡처·분석기",
    )
    p.add_argument("--iface", required=True, help="캡처할 인터페이스 (ip -br link로 확인)")
    p.add_argument("--proto", default="all",
                   help=f"분석할 프로토콜, 쉼표 구분: {','.join(PROTOCOLS)},all (기본 all)")
    p.add_argument("--host", default="", help="이 IP와 주고받은 패킷만, 쉼표 구분 (DNS는 예외)")
    p.add_argument("--port", default="", help="포트 재지정. 예: smtp=2525,pop3=2110,imap=2143")
    p.add_argument("--hex", action="store_true", help="패킷마다 원본 바이트 hex 덤프도 출력")
    p.add_argument("--log", default=None, help="화면 출력을 파일에도 저장 (예: results/http.txt)")
    p.add_argument("--pcap", default=None, help="캡처한 프레임을 pcap으로 저장 (예: results/http.pcap)")
    p.add_argument("--count", type=int, default=0, help="N개 패킷을 받으면 종료 (기본: Ctrl+C까지)")
    args = p.parse_args(argv)
    if args.count < 0:
        p.error("--count는 0 이상이어야 함 (0 = Ctrl+C까지)")

    names = {s.strip().lower() for s in args.proto.split(",") if s.strip()}
    if "all" in names or not names:
        names = set(PROTOCOLS)
    unknown = names - set(PROTOCOLS)
    if unknown:
        p.error(f"모르는 프로토콜: {','.join(sorted(unknown))}")
    args.protos = frozenset(names)

    args.hosts = [h.strip() for h in args.host.split(",") if h.strip()]
    for h in args.hosts:
        # inet_aton은 "8.8.8"도 받아 엉뚱한 주소로 거르고, "10.0.0.300"이면 캡처 시작 때 죽는다
        # → 여기서 점 4개짜리 IPv4만 받는다.
        try:
            ipaddress.IPv4Address(h)
        except ValueError:
            p.error(f"--host 값이 IPv4 주소가 아님: {h} (예: 34.223.124.45)")

    ports = dict(DEFAULT_PORTS)
    for item in filter(None, (s.strip() for s in args.port.split(","))):
        name, _, value = item.partition("=")
        name = name.strip().lower()
        if name not in ports or not value.strip().isdigit() or not 1 <= int(value) <= 65535:
            p.error(f"--port 형식이 잘못됨: {item} (예: smtp=2525, 포트는 1~65535)")
        ports[name] = (int(value),)
    args.ports = ports
    return args


# -----------------------------------------------------------------------------
# 아직 구현되지 않은 모듈(NotImplementedError)이 있어도 캡처·decode는 돌도록 하는 장치.
# NotImplementedError만 잡는다 → 진짜 버그(다른 예외)는 그대로 드러난다.
# -----------------------------------------------------------------------------
_disabled: set[str] = set()


def _try(stage: str, fn, *args, **kwargs):
    """fn(*args) 호출. 미구현이면 경고를 한 번만 찍고 그 단계를 끈 뒤 None."""
    if stage in _disabled:
        return None
    try:
        return fn(*args, **kwargs)
    except NotImplementedError:
        _disabled.add(stage)
        print(f"[main] {stage} 미구현 — 이 단계는 건너뜁니다", file=sys.stderr)
        return None


def _fallback_print(pkt: PacketInfo) -> None:
    """output.print_packet이 준비되기 전 임시 한 줄 출력."""
    ports = f":{pkt.src_port} -> " if pkt.src_port is not None else " -> "
    dport = f":{pkt.dst_port}" if pkt.dst_port is not None else ""
    flags = f" [{pkt.tcp['flags']}]" if pkt.tcp and pkt.tcp.get("flags") else ""
    app = f" {pkt.app.name}: {pkt.app.summary}" if pkt.app else ""
    print(f"#{pkt.no} {pkt.direction} {pkt.proto} {pkt.src_ip}{ports}{pkt.dst_ip}{dport}"
          f"{flags} ttl={pkt.ip['ttl']} len={pkt.frame_len}{app}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # bash에서 '&'로 띄우면 SIGINT가 무시 상태로 물려받아질 수 있다 → Ctrl+C 처리를 되살린다.
    # SIGTERM(kill, timeout 기본 신호)도 같은 방식으로 정상 종료 → 남은 결과 출력.
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.default_int_handler)

    cap_filter = CaptureFilter(iface=args.iface, protos=args.protos, ports=args.ports,
                               hosts=args.hosts)
    tcp = TcpTracker()
    route = RouteTracker()
    # 저장 파일은 캡처 전에 연다. 폴더가 없거나 권한이 없으면 여기서 알리고 끝낸다.
    try:
        pcap = _try("PcapWriter", PcapWriter, args.pcap) if args.pcap else None
        if args.log:
            _try("open_log", output.open_log, args.log)
    except OSError as e:
        print(f"저장 파일을 열 수 없습니다: {e.filename} ({e.strerror})\n"
              f"  → 폴더가 있는지, 쓸 권한이 있는지 확인하세요.", file=sys.stderr)
        return 1

    received = 0
    try:
        for captured in capture(cap_filter):
            if pcap is not None:
                _try("PcapWriter.write", pcap.write, captured)
            pkt = decode(captured, args.ports)
            if pkt is not None:
                conn = _try("TcpTracker.add", tcp.add, pkt)
                _try("RouteTracker.add", route.add, pkt)
                _try("print_packet", output.print_packet, pkt, hex=args.hex)
                if "print_packet" in _disabled:
                    _fallback_print(pkt)
                if conn is not None:
                    _try("print_connection", output.print_connection, conn)
            received += 1
            if args.count and received >= args.count:
                break
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("raw socket을 열 권한이 없습니다. sudo로 실행하세요.", file=sys.stderr)
        return 1
    except OSError as e:
        if e.errno in (errno.ENODEV, errno.ENXIO):
            print(f"인터페이스 '{args.iface}'가 없습니다.\n"
                  f"  → ip -br link 로 인터페이스 이름을 확인하세요.", file=sys.stderr)
            return 1
        raise

    # 정리하는 동안 Ctrl+C가 한 번 더 와도 결과가 끊기지 않게 한다.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)

    for conn in _try("TcpTracker.remaining", tcp.remaining) or []:
        _try("print_connection", output.print_connection, conn)
    for dst, hops in (_try("RouteTracker.hops", route.hops) or {}).items():
        _try("print_route", output.print_route, dst, hops)

    if pcap is not None:
        _try("PcapWriter.close", pcap.close)
    if args.log:
        _try("close_log", output.close_log)
    return 0


if __name__ == "__main__":
    sys.exit(main())
