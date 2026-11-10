# =============================================================================
# 담당자  : D
# 맡은 기능: CSV(results/*.csv) → 그래프 (matplotlib)
#            - 실험 A: 조건별 평균·최대·표준편차 막대 그래프
#            - 실험 B: 조건별 단계 누적 막대 그래프 (dns → tcp_connect → http_first_byte)
# 완료 기준: 설계안 출력 예시 모양의 타임라인이 찍힌다. CSV가 2.6 형식으로 쌓인다.
#            조건별 평균·최대·표준편차 그래프와 단계 누적 막대 그래프가 나온다.
# =============================================================================
from __future__ import annotations


def plot_dns_stats(csv_path: str, out_path: str) -> None:
    """실험 A CSV → 평균·최대·표준편차 막대 그래프 이미지."""
    raise NotImplementedError


def plot_stage_stack(csv_path: str, out_path: str) -> None:
    """실험 B CSV → 단계 누적 막대 그래프 이미지."""
    raise NotImplementedError


if __name__ == "__main__":
    raise NotImplementedError
