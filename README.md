# 🦐 wireshrimp

**Raw Socket 기반 웹 접속 과정·지연 분석기**

웹 페이지를 한 번 열 때 일어나는 **DNS → 경로 → TCP 연결 → HTTP → 연결 해제**를 내 PC가 주고받은 패킷으로 직접 잡아 하나의 흐름으로 보여 주고, 단계별·구간별 지연을 측정해 DNS 서버·네트워크 환경별로 비교합니다.

> 컴퓨터네트워크설계 팀 프로젝트 · 팀 **Wireshrimp** · 자세한 설계는 [docs/DESIGN.md](docs/DESIGN.md)

```
F1 캡처 ──▶ F2 계층별 해석 ──▶ F3 접속 단위로 묶기 ──▶ F4 지연 측정 ──▶ F5 출력·CSV ──▶ 비교 실험·그래프
(Captured)    (PacketInfo)        (Session)              (LatencyResult)    (화면, .csv)
```

출력 예시 (목표):

```
[DNS] OUT 10.0.2.15 -> 8.8.8.8 query A neverssl.com id=0x1a2b
[DNS] IN 8.8.8.8 -> 10.0.2.15 answer 34.223.124.45        (40 ms)
[ROUTE] hop 1 192.168.0.1 2 ms
[ROUTE] hop 2 * * *        (no reply)
[TCP] OUT SYN -> IN SYN/ACK -> OUT ACK port 51234 -> 80 (connect 144 ms)
[HTTP] OUT GET / HTTP/1.1 -> IN HTTP/1.1 200 OK         (first byte 157 ms)
[TCP] OUT FIN/ACK -> IN FIN/ACK -> OUT ACK               (closed, total 352 ms)
```

---

## 환경

| 항목 | 내용 |
|---|---|
| 운영체제 | Ubuntu 22.04 이상 (윈도우 PC는 VirtualBox **브리지 모드**) |
| 언어 | Python 3 — `socket`, `struct`만 사용 (**scapy, libpcap 금지**). 그래프만 matplotlib |
| 권한 | `sudo` (AF_PACKET raw socket) |
| 트래픽 발생 | `curl http://neverssl.com`, `dig`, `traceroute` |
| 검증 | Wireshark 캡처와 필드 값 비교 |

## 실행 방법

```bash
git clone https://github.com/Wireshrimp-2026/wireshrimp.git
cd wireshrimp
```

분석기 실행 (저장소 루트에서, 캡처는 `Ctrl+C`로 종료):

```bash
sudo python3 -m src.main --target neverssl.com --dns-server google --network school-wifi --csv results/exp_a.csv
```

다른 터미널에서 트래픽 발생:

```bash
curl http://neverssl.com
```

| 옵션 | 필수 | 설명 |
|---|---|---|
| `--target` | ✅ | 분석할 도메인 (예: `neverssl.com`) |
| `--dns-server` | ✅ | 실험 조건 라벨 — DNS 서버 (예: `isp`, `google`, `cloudflare`) |
| `--network` | ✅ | 실험 조건 라벨 — 네트워크 (예: `school-wifi`, `home-wifi`, `hotspot`) |
| `--csv` | | 결과를 쌓을 CSV 경로 |

테스트 실행:

```bash
python3 -m unittest discover -s tests -t .
```

## 폴더 구조

```
wireshrimp/
├─ README.md
├─ docs/
│  └─ DESIGN.md              설계 문서 (데이터·함수 약속)          공용
├─ src/
│  ├─ main.py                실행 시작점, 옵션 처리, 전체 연결       A
│  ├─ models.py              데이터 형식 (dataclass)               A · 수정은 팀 합의
│  ├─ capture.py             F1 캡처                              A
│  ├─ decode/
│  │  ├─ __init__.py         decode() — 계층 파서 합치기            A
│  │  ├─ link_ip.py          Ethernet, IP                         A
│  │  ├─ transport.py        TCP, UDP, ICMP                       B
│  │  ├─ app_dns.py          DNS                                  C
│  │  └─ app_http.py         HTTP                                 C
│  ├─ session.py             F3 접속 단위로 묶기                   B
│  ├─ latency.py             F4 지연 측정                          C
│  └─ output.py              F5 화면 출력 + CSV                    D
├─ experiments/
│  ├─ run_dns_exp.sh         실험 A: DNS 서버별 dig 반복           D
│  ├─ run_net_exp.sh         실험 B: curl + traceroute 반복        D
│  ├─ domains.txt            실험용 도메인 목록                     D
│  └─ plot.py                CSV → 막대 그래프                     D
├─ tests/
│  ├─ samples/               Wireshark에서 뽑은 hex 샘플            각자
│  ├─ test_link_ip.py                                             A
│  ├─ test_transport.py  test_session.py                          B
│  ├─ test_dns.py  test_http.py  test_latency.py                  C
│  └─ test_output.py                                              D
└─ results/                  실험 CSV, 그래프 이미지                 D
```

## 역할 분배

팀원: **김준서 · 오현근 · 라승민 · 강정란** (A~D 배정은 팀에서 결정)

| 담당 | 맡는 부분 | 핵심 산출물 |
|---|---|---|
| **A — 캡처·통합** | F1 캡처 (AF_PACKET, OUT/IN 판별, 필터, 시각 기록) · Ethernet/IP 파싱 · `decode()` · `models.py` · `main.py` · README · Wireshark 검증 | 패킷이 잡혀서 `PacketInfo`로 나오는 것 |
| **B — 전송 계층·접속 묶기** | TCP/UDP/ICMP 파싱 (ICMP 안 원본 IP·UDP 포함) · F3 접속 묶기 (DNS 응답 IP ↔ SYN, 4개 묶음, HTTP·FIN·traceroute 붙이기) | `Session` 목록 |
| **C — 응용 계층·지연 측정** | DNS 파싱 (이름 압축 포인터 포함) · HTTP 파싱 · F4 지연 측정 (Transaction ID, 4개 묶음, ICMP 원본 포트 짝) | `LatencyResult` |
| **D — 출력·실험** | F5 실시간 출력·타임라인·CSV · 비교 실험 A·B 스크립트와 측정 · 그래프 (평균·최대·표준편차, 단계 누적 막대) | CSV + 그래프 |

### 완료 기준

- [ ] **A** — `sudo` 실행 시 `curl http://neverssl.com` 트래픽이 OUT/IN 구분되어 PacketInfo로 나온다. IP·TTL이 Wireshark와 일치한다.
- [ ] **B** — Seq/Ack/Flags가 Wireshark와 일치한다. 접속 1회가 Session 1개로 묶이고, SYN·SYN/ACK·ACK·FIN이 모두 붙는다. traceroute 프로브와 ICMP 응답이 짝지어진다.
- [ ] **C** — DNS 질의 도메인·응답 IP, HTTP 메서드·상태 코드가 Wireshark와 일치한다. dns_ms, tcp_connect_ms, http_first_byte_ms, total_ms, 홉별 지연이 계산된다.
- [ ] **D** — 설계안 출력 예시 모양의 타임라인이 찍힌다. CSV가 2.6 형식으로 쌓인다. 조건별 평균·최대·표준편차 그래프와 단계 누적 막대 그래프가 나온다.

### 공통 약속

- 데이터 형식은 [`src/models.py`](src/models.py) 하나에만 정의한다. **팀 합의 없이 고치지 않는다.**
- 공개 함수(각 파일에 이미 정의된 함수)의 **이름·입력·출력은 바꾸지 않는다.** 도우미 함수는 자유롭게 추가.
- 파서(`parse_*`)는 데이터가 짧거나 깨졌으면 `ValueError`를 던진다. `decode()`는 이를 잡아 해당 부분만 `None`으로 두고 계속 진행한다.
- 측정할 수 없는 값은 **0이 아니라 `None`**.

## 개발 규칙 (GitHub)

| 규칙 | 내용 |
|---|---|
| 저장소 | 조직 [`Wireshrimp-2026`](https://github.com/orgs/Wireshrimp-2026/repositories) 아래 `wireshrimp` 1개 |
| `main` | **항상 실행되는 상태** 유지 |
| 브랜치 | `feat/capture` · `feat/transport` · `feat/session` · `feat/dns-http` · `feat/latency` · `feat/output` · `feat/experiments` |
| 바로 push | **내 파일만 고치는 작은 수정** (push 전 `git pull` 필수) |
| main 직접 push | **단순 버그 수정, 주석·오타 수정** → PR 없이 `main`에 바로 push 가능 (push 전 `git pull` 필수) |
| PR 필요 | **새 기능, 큰 수정, 남의 파일, `models.py`, `main.py`** → 한 명 이상 확인 후 merge |
| 커밋 메시지 | 기능 번호를 앞에: `[F3] SYN 4개 묶음 추적 추가` |

```bash
git switch -c feat/transport
```

```bash
git pull --rebase origin main && git push -u origin feat/transport
```

## 일정

| 날짜 | 할 일 |
|---|---|
| ~11/13(금) 19:00 | 설계계획서 PPT 5장 제출 |
| 11/14(토) | 저장소·뼈대 완성 |
| 11/14~19 | 각자 자기 파일 개발 + 샘플로 단위 테스트 |
| 11/17(화) | 중간 점검: 캡처 + decode가 PacketInfo를 내놓는지 |
| 11/20~21 | 통합: `curl`, `dig`, `traceroute`로 끝까지 + Wireshark 비교 |
| 11/22~25 | 실험 A·B (조건별 30회) + 그래프 |
| ~11/27(금) 19:00 | 설계보고서 PPT 8장 + 소스 제출 |
