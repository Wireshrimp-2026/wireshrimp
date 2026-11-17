#!/usr/bin/env bash
# =============================================================================
# 담당자  : A
# 맡은 기능: 실험 A — DNS 서버별 응답 시간 (통신사 기본 · Google 8.8.8.8 · Cloudflare 1.1.1.1)
#            domains.txt의 도메인을 번갈아 dig @서버 로 조건별 30회 반복
#            (캐시 주의: 첫 질의와 반복 질의를 따로 기록)
#            - dig -4 @서버 A 도메인  (@서버를 주면 로컬 resolved 캐시를 거치지 않음)
#            - 분석기는 도메인마다 --target으로 실행, sudo timeout -s INT <초> 로 자동 종료
# 완료 기준: sudo 실행 시 curl http://neverssl.com 트래픽이 OUT/IN 구분되어
#            PacketInfo로 나온다. IP·TTL이 Wireshark와 일치한다.
#            실험 스크립트로 조건별 반복 실행 시 CSV가 쌓인다.
# =============================================================================
# 사용법 (저장소 루트에서):
#   sudo experiments/run_dns_exp.sh <iface> <network-label> [반복횟수]
#   예) sudo experiments/run_dns_exp.sh wlo1 school-wifi 30
#
# 환경 변수로 바꿀 수 있는 값 (sudo 뒤에 쓸 것: sudo ISP_DNS=1.2.3.4 experiments/run_dns_exp.sh ...
#                              sudo 앞에 쓰면 sudo가 지워 버려 적용되지 않음):
#   ISP_DNS   통신사 DNS IP (기본: resolvectl에서 자동으로 찾음)
#   SERVERS   실험할 서버 라벨 목록 (기본: "isp google cloudflare")
#   WAIT      분석기 시작 후 dig까지 기다리는 초 (기본: 1)
#   CAPTURE   분석기 1회 최대 실행 시간 초 (기본: 6, 보통은 dig 끝나면 바로 종료)
#
# 결과 (서버마다 반복횟수만큼, 도메인은 번갈아 가며):
#   results/exp_a_first.csv   도메인별 첫 질의 (서버 쪽 캐시가 비어 있을 가능성이 큼)
#   results/exp_a.csv         같은 도메인의 두 번째 이후 질의 (반복 질의)
#   results/raw/exp_a_*.log   분석기 화면 출력 (git에는 올리지 않음)
set -euo pipefail

usage() { sed -n '13,27p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

[[ $# -ge 2 ]] || usage
IFACE=$1
NETWORK=$2
COUNT=${3:-30}
SERVERS=${SERVERS:-"isp google cloudflare"}
WAIT=${WAIT:-1}
CAPTURE=${CAPTURE:-6}
# root로 돌린 파이썬이 src/__pycache__를 root 소유로 만들지 않게
export PYTHONDONTWRITEBYTECODE=1

if [[ $EUID -ne 0 ]]; then
    echo "raw socket 캡처를 위해 sudo로 실행하세요." >&2
    exit 1
fi
command -v dig >/dev/null || { echo "dig가 없습니다: sudo apt install dnsutils" >&2; exit 1; }

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

# 도메인 목록 (주석·빈 줄 제외)
mapfile -t DOMAINS < <(grep -vE '^\s*(#|$)' experiments/domains.txt)
[[ ${#DOMAINS[@]} -gt 0 ]] || { echo "experiments/domains.txt가 비어 있습니다." >&2; exit 1; }

isp_dns() {
    if [[ -n ${ISP_DNS:-} ]]; then echo "$ISP_DNS"; return; fi
    # resolvectl에서 현재 인터페이스의 첫 IPv4 DNS 서버
    # (못 찾아도 set -e/pipefail로 스크립트가 조용히 죽지 않게 || true — 아래에서 안내)
    { resolvectl dns "$IFACE" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1; } || true
}

server_ip() {
    case $1 in
        isp)        isp_dns ;;
        google)     echo 8.8.8.8 ;;
        cloudflare) echo 1.1.1.1 ;;
        *)          echo "$1" ;;   # 라벨 대신 IP를 직접 줘도 됨
    esac
}

for label in $SERVERS; do
    ip=$(server_ip "$label")
    if [[ -z $ip ]]; then
        echo "[$label] DNS 서버 IP를 찾지 못했습니다. ISP_DNS=x.x.x.x 로 지정하세요." >&2
        exit 1
    fi
    echo "=== 서버 $label ($ip), 네트워크 $NETWORK, ${COUNT}회 (도메인 ${#DOMAINS[@]}개 번갈아)"

    # 조건(서버)별 COUNT회. 도메인은 domains.txt 순서대로 돌아가며 하나씩 질의한다.
    # 각 도메인의 첫 질의 → exp_a_first.csv, 같은 도메인의 두 번째 이후 → exp_a.csv
    for ((i = 1; i <= COUNT; i++)); do
        domain=${DOMAINS[$(( (i - 1) % ${#DOMAINS[@]} ))]}
        if [[ $i -le ${#DOMAINS[@]} ]]; then csv=results/exp_a_first.csv; else csv=results/exp_a.csv; fi
        log=results/raw/exp_a_${label}.log
        echo "--- run $i $domain" >>"$log"
        # 분석기를 먼저 띄우고 → dig → 응답이 오면 바로 SIGINT(=Ctrl+C)로 끝낸다.
        # CAPTURE는 dig가 멈췄을 때를 위한 상한, -k는 그래도 안 끝나면 강제 종료.
        timeout -s INT -k 5 "$CAPTURE" python3 -u -m src.main \
            --iface "$IFACE" --target "$domain" \
            --dns-server "$label" --network "$NETWORK" --csv "$csv" \
            >>"$log" 2>&1 &
        pid=$!
        sleep "$WAIT"
        dig -4 +tries=1 +time=2 @"$ip" A "$domain" >/dev/null || echo "  dig 실패: $domain" >&2
        sleep 0.3                          # 응답 패킷이 분석기에 도착할 여유
        kill -INT "$pid" 2>/dev/null || true   # timeout이 분석기에게 SIGINT를 전달
        wait "$pid" || true                # timeout은 종료 코드 124를 돌려줄 수 있음
        pid=""
        printf '  [%s] %2d/%d %s\n' "$label" "$i" "$COUNT" "$domain"
    done
done

echo "완료: results/exp_a_first.csv, results/exp_a.csv"
