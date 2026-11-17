# =============================================================================
# 담당자  : A (수정은 PR + 한 명 이상 확인)
# 맡은 기능: 실행 시작점 — 옵션 처리, F1 → F2 → F3 → F4 → F5 전체 연결
#            (F3 접속 묶기와 경로 추적 결과를 합쳐 Session·LatencyResult 완성)
#            sudo python3 -m src.main --iface wlo1 --target neverssl.com --dns-server google \
#                 --network school-wifi --csv results/exp_a.csv
# 완료 기준: sudo 실행 시 curl http://neverssl.com 트래픽이 OUT/IN 구분되어
#            PacketInfo로 나온다. IP·TTL이 Wireshark와 일치한다.
#            실험 스크립트로 조건별 반복 실행 시 CSV가 쌓인다.
# =============================================================================
from __future__ import annotations

import argparse
import errno
import signal
import sys

from .capture import CaptureFilter, capture
from .decode import decode
from .latency import measure
from .models import PacketInfo
from .output import CsvWriter, print_packet, print_timeline
from .route import RouteTracker, hop_delays
from .session import SessionBuilder


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python3 -m src.main",
        description="Raw Socket 기반 웹 접속 과정·지연 분석기",
    )
    p.add_argument("--iface", required=True, help="캡처할 인터페이스 (예: wlo1, enp0s3 — ip -br link로 확인)")
    p.add_argument("--target", required=True, help="분석할 도메인 (예: neverssl.com)")
    p.add_argument("--dns-server", required=True, help="실험 조건 라벨: DNS 서버 (예: google)")
    p.add_argument("--network", required=True, help="실험 조건 라벨: 네트워크 (예: school-wifi)")
    p.add_argument("--csv", default=None, help="결과 CSV 경로 (예: results/exp_a.csv)")
    return p.parse_args(argv)


# -----------------------------------------------------------------------------
# 아직 구현되지 않은 팀원 모듈(NotImplementedError)이 있어도 캡처·decode는 돌도록 하는 장치.
# NotImplementedError만 잡는다 → 진짜 버그(다른 예외)는 그대로 드러난다.
# -----------------------------------------------------------------------------
_disabled: set[str] = set()


def _try(stage: str, fn, *args):
    """fn(*args) 호출. 미구현이면 경고를 한 번만 찍고 그 단계를 끈 뒤 None."""
    if stage in _disabled:
        return None
    try:
        return fn(*args)
    except NotImplementedError:
        _disabled.add(stage)
        print(f"[main] {stage} 미구현 — 이 단계는 건너뜁니다", file=sys.stderr)
        return None


def _fallback_print(pkt: PacketInfo) -> None:
    """output.print_packet(D)이 준비되기 전 임시 한 줄 출력 (중간 점검용)."""
    ports = f" {pkt.src_port}->{pkt.dst_port}" if pkt.src_port is not None else ""
    flags = f" [{pkt.tcp_flags}]" if pkt.tcp_flags else ""
    print(f"[{pkt.proto}] {pkt.direction} {pkt.src_ip} -> {pkt.dst_ip}{ports}{flags} "
          f"ttl={pkt.ttl} len={pkt.payload_len}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # 실험 스크립트처럼 bash에서 '&'로 띄우면 SIGINT가 무시(SIG_IGN) 상태로 물려받아져
    # timeout -s INT 가 캡처를 끝내지 못한다 → Ctrl+C 처리를 명시적으로 되살린다.
    # SIGTERM(kill, timeout 기본 신호)도 같은 방식으로 정상 종료 → 결과 출력·CSV 저장.
    signal.signal(signal.SIGINT, signal.default_int_handler)
    signal.signal(signal.SIGTERM, signal.default_int_handler)

    # F1 캡처 준비
    cap_filter = CaptureFilter(iface=args.iface)
    builder = SessionBuilder()   # F3 (B)
    tracker = RouteTracker()     # 경로 (D)

    # F1 캡처 → F2 해석 → (실시간 출력) → F3 묶기 + 경로 추적   (Ctrl+C로 캡처 종료)
    try:
        for captured in capture(cap_filter):
            pkt = decode(captured)
            if pkt is None:
                continue
            _try("print_packet", print_packet, pkt)
            if "print_packet" in _disabled:
                _fallback_print(pkt)
            _try("SessionBuilder.add", builder.add, pkt)
            _try("RouteTracker.add", tracker.add, pkt)
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
        raise   # 그 밖의 OSError(예: 출력 파이프 끊김)는 원인을 가리지 않고 그대로 보여 준다

    # 캡처가 끝난 뒤 결과를 정리하는 동안 Ctrl+C가 한 번 더 오면(두 번 누름, timeout 재전송)
    # CSV 한 줄이 통째로 날아간다 → 이 구간에서는 SIGINT를 무시한다.
    # (멈춰 버리면 SIGTERM 또는 Ctrl+\ 로 끝낼 수 있고, 실험 스크립트는 timeout -k 로 강제 종료)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)

    # 경로 붙이기 → F4 지연 측정 + 홉별 지연 → F5 타임라인 출력 · CSV 저장
    writer = _try("CsvWriter", CsvWriter, args.csv, args.dns_server, args.network) if args.csv else None
    sessions = _try("SessionBuilder.sessions", builder.sessions) or []
    for session in sessions:
        if session.domain != args.target:
            continue
        session.route_probes = _try("RouteTracker.probes_for", tracker.probes_for,
                                    session.server_ip) or []
        result = _try("measure", measure, session)
        if result is None:
            continue
        result.hops = _try("hop_delays", hop_delays, session.route_probes) or []
        _try("print_timeline", print_timeline, session, result)
        if writer is not None:
            _try("CsvWriter.write", writer.write, result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
