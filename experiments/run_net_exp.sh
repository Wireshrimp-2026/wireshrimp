#!/usr/bin/env bash
# =============================================================================
# 담당자  : A
# 맡은 기능: 실험 B — 네트워크별 단계·경로 지연 (학교 Wi-Fi · 집 Wi-Fi · 휴대폰 핫스팟)
#            curl http://neverssl.com 조건별 30회 + traceroute 3회 반복
#            - 매 회 전에 sudo resolvectl flush-caches (안 하면 2회차부터 DNS 패킷이 안 나감)
#            - curl -4, traceroute -4 (IPv6로 나가면 분석기가 못 봄)
#            - 분석기는 sudo timeout -s INT <초> 로 자동 종료
# 완료 기준: sudo 실행 시 curl http://neverssl.com 트래픽이 OUT/IN 구분되어
#            PacketInfo로 나온다. IP·TTL이 Wireshark와 일치한다.
#            실험 스크립트로 조건별 반복 실행 시 CSV가 쌓인다.
# =============================================================================
# 사용법 (저장소 루트에서, 네트워크를 바꿀 때마다 한 번씩 실행):
#   sudo experiments/run_net_exp.sh <iface> <network-label> [반복횟수]
#   예) sudo experiments/run_net_exp.sh wlo1 school-wifi 30
#
# 환경 변수로 바꿀 수 있는 값 (sudo 뒤에 쓸 것: sudo TRACE_COUNT=5 experiments/run_net_exp.sh ...
#                              sudo 앞에 쓰면 sudo가 지워 버려 적용되지 않음):
#   TARGET        분석할 도메인 (기본: neverssl.com)
#   DNS_LABEL     CSV의 dns_server 라벨 (기본: isp — 시스템 기본 DNS 사용)
#   TRACE_COUNT   traceroute를 함께 돌릴 회차 수 (기본: 3, 앞쪽 회차)
#   WAIT          분석기 시작 후 트래픽 발생까지 기다리는 초 (기본: 1)
#   CAPTURE       curl만 할 때 분석기 최대 실행 시간 초 (기본: 15, curl 제한 10초보다 길게)
#   CAPTURE_TRACE traceroute도 할 때 분석기 최대 실행 시간 초 (기본: 60)
#                 (보통은 curl·traceroute가 끝나면 바로 종료하므로 상한일 뿐)
#
# 결과:
#   results/exp_b.csv         회차마다 한 줄 (traceroute 회차는 hop_count·hop_delays 포함)
#   results/raw/exp_b_*.log   분석기 화면 출력 (git에는 올리지 않음)
set -euo pipefail

usage() { sed -n '13,29p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

[[ $# -ge 2 ]] || usage
IFACE=$1
NETWORK=$2
COUNT=${3:-30}
TARGET=${TARGET:-neverssl.com}
DNS_LABEL=${DNS_LABEL:-isp}
TRACE_COUNT=${TRACE_COUNT:-3}
WAIT=${WAIT:-1}
CAPTURE=${CAPTURE:-15}
CAPTURE_TRACE=${CAPTURE_TRACE:-60}
# root로 돌린 파이썬이 src/__pycache__를 root 소유로 만들지 않게
export PYTHONDONTWRITEBYTECODE=1

if [[ $EUID -ne 0 ]]; then
    echo "raw socket 캡처를 위해 sudo로 실행하세요." >&2
    exit 1
fi
command -v curl >/dev/null || { echo "curl이 없습니다: sudo apt install curl" >&2; exit 1; }
if [[ $TRACE_COUNT -gt 0 ]]; then
    command -v traceroute >/dev/null || { echo "traceroute가 없습니다: sudo apt install traceroute" >&2; exit 1; }
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
mkdir -p results/raw
pid=""
cleanup() {
    # timeout은 자기 프로세스 그룹을 따로 만들어서, 스크립트를 Ctrl+C로 멈춰도 분석기에는
    # 신호가 가지 않는다 (그대로 두면 상한 시간까지 돌다가 덜 끝난 회차를 CSV에 써 버림)
    # → 그룹(timeout + 분석기)째 바로 끝내서, 중단된 회차는 CSV에 남기지 않는다.
    if [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null; then
        kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        echo "중단됨: 진행 중이던 회차는 CSV에 기록하지 않았습니다." >&2
    fi
    # sudo로 만든 결과 파일이 root 소유가 되면 나중에 plot.py·git이 못 고친다 → 원래 사용자에게 돌려줌
    if [[ -n ${SUDO_USER:-} ]]; then chown -R "$SUDO_USER": results 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM
CSV=results/exp_b.csv
LOG=results/raw/exp_b_${NETWORK}.log

echo "=== 네트워크 $NETWORK, 대상 $TARGET, ${COUNT}회 (traceroute는 앞 ${TRACE_COUNT}회)"

for ((i = 1; i <= COUNT; i++)); do
    with_trace=0
    [[ $i -le $TRACE_COUNT ]] && with_trace=1
    duration=$CAPTURE
    [[ $with_trace -eq 1 ]] && duration=$CAPTURE_TRACE

    # DNS 캐시를 비워야 매 회 DNS 질의 패킷이 실제로 나간다.
    resolvectl flush-caches 2>/dev/null || true

    echo "--- run $i" >>"$LOG"
    # duration은 상한, -k는 그래도 안 끝나면 강제 종료
    timeout -s INT -k 5 "$duration" python3 -u -m src.main \
        --iface "$IFACE" --target "$TARGET" \
        --dns-server "$DNS_LABEL" --network "$NETWORK" --csv "$CSV" \
        >>"$LOG" 2>&1 &
    pid=$!
    sleep "$WAIT"

    curl -4 -s -o /dev/null --max-time 10 "http://$TARGET/" || echo "  curl 실패 (run $i)" >&2
    if [[ $with_trace -eq 1 ]]; then
        # -n: 홉 IP를 역방향 조회하지 않음 (DNS 패킷이 섞이지 않게)
        # -q 1: 홉마다 프로브 1개 / -w 2: 응답 2초 대기 / -m 30: 최대 30홉
        traceroute -4 -n -q 1 -w 2 -m 30 "$TARGET" >>"$LOG" 2>&1 || echo "  traceroute 실패 (run $i)" >&2
    fi
    # 트래픽이 끝났으면 상한까지 기다리지 않고 분석기를 바로 끝낸다.
    # (마지막 FIN/ACK·ICMP가 도착할 여유를 조금 두고, timeout이 분석기에게 SIGINT를 전달)
    sleep 0.5
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" || true   # timeout은 종료 코드 124를 돌려줄 수 있음
    pid=""

    printf '  [%s] %2d/%d%s\n' "$NETWORK" "$i" "$COUNT" "$([[ $with_trace -eq 1 ]] && echo ' +traceroute')"
done

echo "완료: $CSV"
