# =============================================================================
# 담당자  : A (수정은 PR + 한 명 이상 확인)
# 맡은 기능: 실행 시작점 — 옵션 처리, F1 → F2 → F3 → F4 → F5 전체 연결
#            sudo python3 -m src.main --target neverssl.com --dns-server google \
#                 --network school-wifi --csv results/exp_a.csv
# 완료 기준: sudo 실행 시 curl http://neverssl.com 트래픽이 OUT/IN 구분되어
#            PacketInfo로 나온다. IP·TTL이 Wireshark와 일치한다.
# =============================================================================
from __future__ import annotations

import argparse

from .capture import CaptureFilter, capture
from .decode import decode
from .latency import measure
from .output import CsvWriter, print_packet, print_timeline
from .session import SessionBuilder


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="python3 -m src.main",
        description="Raw Socket 기반 웹 접속 과정·지연 분석기",
    )
    p.add_argument("--target", required=True, help="분석할 도메인 (예: neverssl.com)")
    p.add_argument("--dns-server", required=True, help="실험 조건 라벨: DNS 서버 (예: google)")
    p.add_argument("--network", required=True, help="실험 조건 라벨: 네트워크 (예: school-wifi)")
    p.add_argument("--csv", default=None, help="결과 CSV 경로 (예: results/exp_a.csv)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    # F1 캡처 준비
    cap_filter = CaptureFilter()
    builder = SessionBuilder()

    # F1 캡처 → F2 해석 → (실시간 출력) → F3 묶기   (Ctrl+C로 캡처 종료)
    try:
        for captured in capture(cap_filter):
            pkt = decode(captured)
            if pkt is None:
                continue
            print_packet(pkt)
            builder.add(pkt)
    except KeyboardInterrupt:
        pass

    # F4 지연 측정 → F5 타임라인 출력 · CSV 저장
    writer = CsvWriter(args.csv, args.dns_server, args.network) if args.csv else None
    for session in builder.sessions():
        if session.domain != args.target:
            continue
        result = measure(session)
        print_timeline(session, result)
        if writer is not None:
            writer.write(result)


if __name__ == "__main__":
    main()
