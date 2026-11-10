#!/usr/bin/env bash
# =============================================================================
# 담당자  : A
# 맡은 기능: 실험 B — 네트워크별 단계·경로 지연 (학교 Wi-Fi · 집 Wi-Fi · 휴대폰 핫스팟)
#            curl http://neverssl.com 조건별 30회 + traceroute 3회 반복
# 완료 기준: sudo 실행 시 curl http://neverssl.com 트래픽이 OUT/IN 구분되어
#            PacketInfo로 나온다. IP·TTL이 Wireshark와 일치한다.
#            실험 스크립트로 조건별 반복 실행 시 CSV가 쌓인다.
# =============================================================================
set -euo pipefail

echo "TODO: 실험 B 스크립트 작성" >&2
exit 1
