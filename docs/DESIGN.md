# Raw Socket 기반 웹 접속 과정·지연 분석기 — 뼈대 설계 및 역할 분배

> 기준 문서: 팀 설계안 「Raw Socket 기반 웹 접속 과정·지연 분석기」
> 팀원: 김준서, 오현근, 라승민, 강정란 → 아래에서는 **A, B, C, D**로 부른다. (배정은 팀에서 결정)
> 이 문서는 **코드가 아니라 설계**다. 네 명은 이 문서의 폴더 구조, 데이터 형식, 함수 모양을 그대로 따라 각자 자기 파일을 만든다.

---

## 0. 전제 (설계안 기준)

| 항목 | 내용 |
|---|---|
| 운영체제 | Ubuntu 22.04 이상 (리눅스 PC는 그대로, 윈도우 PC는 VirtualBox 브리지 모드) |
| 언어 | Python 3 — `socket`, `struct`만 사용 (scapy, libpcap 금지). 그래프만 matplotlib |
| 실행 | `sudo` |
| 필수 | HTTP, DNS / IP·TCP·UDP 헤더 / TCP 연결 설정·전송·해제 추적 / 송수신 모두 캡처 |
| 선택 | traceroute (UDP 프로브 + ICMP Time Exceeded) |
| 트래픽 발생 | `curl http://neverssl.com`, `dig`, `traceroute` |
| 검증 | Wireshark 캡처와 필드 값 비교 |

> ⚠ 설계안에 "확정 필요"로 남은 것: 운영체제/VirtualBox 브리지 모드, 언어(C+Python 안). 이 문서는 **Python 단일 언어**를 전제로 한다.

---

## 1. 전체 흐름

```
F1 캡처 ──▶ F2 계층별 해석 ──▶ F3 접속 단위로 묶기 ──▶ F4 지연 측정 ──▶ F5 출력·CSV ──▶ 비교 실험·그래프
(Captured)    (PacketInfo)        (Session)              (LatencyResult)    (화면, .csv)
```

각 화살표에서 넘기는 데이터의 모양(= **약속**)은 2장에 고정한다. 모양만 지키면 서로의 코드 내부를 몰라도 합칠 수 있다.

---

## 2. 데이터 약속 (모든 팀원 공통)

모든 형식은 `src/models.py` 한 파일에 `dataclass`로 정의한다. **이 파일은 팀 합의 없이 고치지 않는다.** (고칠 땐 PR + 단톡방 공지)

### 2.1 Captured — F1 → F2
| 필드 | 타입 | 설명 |
|---|---|---|
| `ts` | float | 받은 시각 (초 단위, `time.time()`) |
| `direction` | str | `"OUT"`(pkttype == PACKET_OUTGOING(4)) / `"IN"`(그 외) |
| `frame` | bytes | 이더넷 헤더부터 시작하는 프레임 전체 |

### 2.2 PacketInfo — F2 → F3 (설계안의 "패킷 정보 1건 형식")
| 필드 | 타입 | 채우는 사람 | 설명 |
|---|---|---|---|
| `ts`, `direction` | float, str | A | Captured에서 그대로 |
| `src_mac`, `dst_mac` | str | A | `"aa:bb:cc:dd:ee:ff"` |
| `src_ip`, `dst_ip` | str | A | `"10.0.2.15"` |
| `ttl` | int | A | |
| `proto` | str | A | `"TCP"` / `"UDP"` / `"ICMP"` / `"OTHER"` |
| `src_port`, `dst_port` | int \| None | B | TCP/UDP일 때만 |
| `tcp_flags` | str \| None | B | `"SYN"`, `"SYN,ACK"`, `"FIN,ACK"` 형식 (대문자, 쉼표, 고정 순서: SYN,FIN,RST,PSH,ACK) |
| `seq`, `ack` | int \| None | B | TCP일 때만 |
| `window` | int \| None | B | TCP일 때만 |
| `udp_length` | int \| None | B | UDP일 때만 |
| `icmp_type`, `icmp_code` | int \| None | D | ICMP일 때만 |
| `icmp_orig_dst_ip` | str \| None | D | ICMP 안에 담긴 원본 IP 헤더의 목적지 |
| `icmp_orig_dst_port` | int \| None | D | ICMP 안에 담긴 원본 UDP 목적지 포트 (traceroute 짝 맞추기용) |
| `payload_len` | int | B | 전송 계층 헤더를 뗀 데이터 길이 |
| `dns` | DnsInfo \| None | C | 53번 포트일 때 |
| `http` | HttpInfo \| None | C | 80번 포트이고 데이터가 있을 때 |

### 2.3 DnsInfo / HttpInfo — F2 내부 (C가 채움)
**DnsInfo**
| 필드 | 타입 | 설명 |
|---|---|---|
| `txid` | int | Transaction ID |
| `is_response` | bool | QR 비트 |
| `qname` | str | `"neverssl.com"` |
| `qtype` | str | `"A"`, `"AAAA"`, `"CNAME"` 등 |
| `answers` | list[(str, int)] | `[(응답 IP, TTL), ...]` — A 레코드만 |

**HttpInfo**
| 필드 | 타입 | 설명 |
|---|---|---|
| `is_request` | bool | |
| `method`, `url`, `host` | str \| None | 요청일 때 |
| `status_code`, `reason` | int \| None, str \| None | 응답일 때 (`200`, `"OK"`) |
| `content_length` | int \| None | 헤더에 있을 때 |

> HTTP는 **요청/응답의 첫 줄과 헤더가 있는 패킷**에서만 채운다. 응답 본문이 이어지는 나머지 패킷은 `http = None`, `payload_len > 0`.

### 2.4 Session — F3 → F4 (웹 접속 1회)
| 필드 | 타입 | 설명 |
|---|---|---|
| `domain` | str | DNS 질의 도메인 |
| `server_ip` | str | DNS 응답 IP |
| `dns_query`, `dns_response` | PacketInfo \| None | txid로 짝지은 질의/응답 |
| `conn_key` | (str, int, str, int) \| None | (내 IP, 내 포트, 서버 IP, 서버 포트) |
| `syn`, `synack`, `handshake_ack` | PacketInfo \| None | 3-way handshake |
| `http_request` | PacketInfo \| None | 첫 GET |
| `http_first_response` | PacketInfo \| None | 데이터가 있는 첫 응답(IN) |
| `fin_packets` | list[PacketInfo] | FIN 교환 + 마지막 ACK |
| `route_probes` | list[(PacketInfo, PacketInfo \| None)] | (traceroute UDP 프로브, 짝지은 ICMP 응답 또는 None) |
| `packets` | list[PacketInfo] | 이 접속에 속한 모든 패킷 (시간순, 타임라인 출력용) |

### 2.5 LatencyResult — F4 → F5
| 필드 | 타입 | 설명 |
|---|---|---|
| `domain`, `server_ip` | str | |
| `dns_ms` | float \| None | 질의(OUT) → 응답(IN) |
| `tcp_connect_ms` | float \| None | SYN(OUT) → SYN+ACK(IN) |
| `http_first_byte_ms` | float \| None | GET(OUT) → 데이터 있는 첫 응답(IN) |
| `total_ms` | float \| None | DNS 질의 → 마지막 FIN/ACK |
| `hops` | list[(int, str \| None, float \| None)] | `[(홉 번호, 라우터 IP, 지연 ms), ...]` — 무응답은 `None` |

> 측정할 수 없는 값은 **0이 아니라 None**. (0과 "측정 못 함"을 구분해야 그래프가 정확함)

### 2.6 CSV 형식 — F5 출력 (설계안 기준)
```
measured_at, dns_server, network, domain, dns_ms, tcp_connect_ms, http_first_byte_ms, total_ms, hop_count, hop_delays
```
- `measured_at`: `2026-11-20T14:03:11`
- `dns_server`, `network`: 실행할 때 옵션으로 받은 실험 조건 라벨 (예: `google`, `school-wifi`)
- `hop_delays`: `"2.1;*;14.8;..."` (세미콜론 구분, 무응답은 `*`)
- 값이 None이면 빈 칸

---

## 3. 함수 약속 (파일별 공개 함수)

> 각자 파일 안에 도우미 함수는 마음대로 추가해도 된다. **아래 공개 함수의 이름·입력·출력만 바꾸지 않는다.**

| 파일 | 공개 함수 | 입력 → 출력 | 담당 |
|---|---|---|---|
| `capture.py` | `capture(filter)` | 필터 설정 → `Captured`를 하나씩 내보내는 제너레이터 | A |
| `capture.py` | `CaptureFilter` | 대상 서버 IP 목록, 포트(53, 80), ICMP 허용, traceroute 포트 범위 | A |
| `decode/link_ip.py` | `parse_ethernet(frame)` | bytes → (MAC 정보, EtherType, 나머지 bytes) | A |
| `decode/link_ip.py` | `parse_ip(data)` | bytes → (IP 필드 dict, 나머지 bytes) | A |
| `decode/transport.py` | `parse_tcp(data)`, `parse_udp(data)` | bytes → (필드 dict, 나머지 bytes) | B |
| `decode/icmp.py` | `parse_icmp(data)` | bytes → (필드 dict, 나머지 bytes) | D |
| `decode/app_dns.py` | `parse_dns(data)` | bytes → `DnsInfo` | C |
| `decode/app_http.py` | `parse_http(data)` | bytes → `HttpInfo` 또는 None (첫 줄이 HTTP가 아니면) | C |
| `decode/__init__.py` | `decode(captured)` | `Captured` → `PacketInfo` 또는 None (IPv4 아님 등). 위 함수들을 차례로 호출해 하나로 합침 | A |
| `session.py` | `SessionBuilder.add(pkt)` / `.sessions()` | PacketInfo를 하나씩 받음 → 완성된 `Session` 목록 | B |
| `route.py` | `RouteTracker.add(pkt)` / `.probes_for(server_ip)` | PacketInfo를 하나씩 받음 → 해당 서버로 보낸 `[(프로브, ICMP 응답 또는 None), ...]` | D |
| `route.py` | `hop_delays(probes)` | `[(프로브, 응답)]` → `[(홉 번호, 라우터 IP, 지연 ms)]` (무응답은 None) | D |
| `latency.py` | `measure(session)` | `Session` → `LatencyResult` (dns·tcp·http·total, `hops`는 빈 목록) | C |
| `output.py` | `print_packet(pkt)` | 실시간 한 줄 출력 (`[DNS] OUT ...` 형식) | D |
| `output.py` | `print_timeline(session, result)` | 접속 1회 요약 타임라인 출력 | D |
| `output.py` | `CsvWriter(path, dns_server, network).write(result)` | LatencyResult → CSV 한 줄 | D |
| `experiments/plot.py` | `plot_dns_stats(csv, out)`, `plot_stage_stack(csv, out)` | CSV → 그래프 이미지 | C |

**연결 순서 (`main.py`, A)**: `SessionBuilder`(B)와 `RouteTracker`(D)에 같은 패킷을 넣고, 세션마다 `session.route_probes = tracker.probes_for(session.server_ip)` → `result = measure(session)`(C) → `result.hops = hop_delays(session.route_probes)`(D) 순서로 채운다.

**에러 처리 약속**
- 파서(`parse_*`)는 데이터가 짧거나 깨졌으면 `ValueError`를 던진다.
- `decode()`(A)는 하위 파서의 예외를 잡아서 해당 부분만 None으로 두고 계속 진행한다. → 한 사람의 버그가 프로그램 전체를 멈추지 않는다.

---

## 4. 폴더 구조

```
wireshrimp/
├─ README.md                  실행 방법, 팀 규칙                     (A)
├─ docs/
│  └─ DESIGN.md              이 문서                               (공용)
├─ src/
│  ├─ main.py                실행 시작점, 옵션 처리, 전체 연결        (A)
│  ├─ models.py              2장의 데이터 형식 (dataclass)           (A, 수정은 팀 합의)
│  ├─ capture.py             F1                                    (A)
│  ├─ decode/
│  │  ├─ __init__.py         decode() — 계층 파서 합치기             (A)
│  │  ├─ link_ip.py          Ethernet, IP                          (A)
│  │  ├─ transport.py        TCP, UDP                              (B)
│  │  ├─ icmp.py             ICMP                                  (D)
│  │  ├─ app_dns.py          DNS                                   (C)
│  │  └─ app_http.py         HTTP                                  (C)
│  ├─ session.py             F3 접속 단위로 묶기                    (B)
│  ├─ route.py               traceroute 경로 추적·홉별 지연          (D)
│  ├─ latency.py             F4 단계별 지연 측정                    (C)
│  └─ output.py              F5 화면 출력 + CSV                     (D)
├─ experiments/
│  ├─ run_dns_exp.sh         실험 A: DNS 서버별 dig 반복            (A)
│  ├─ run_net_exp.sh         실험 B: curl + traceroute 반복         (A)
│  ├─ domains.txt            실험용 도메인 목록                      (A)
│  └─ plot.py                CSV → 막대 그래프                      (C)
├─ tests/
│  ├─ samples/               Wireshark에서 뽑은 hex 샘플             (각자)
│  ├─ test_link_ip.py                                              (A)
│  ├─ test_transport.py      test_session.py                       (B)
│  ├─ test_dns.py  test_http.py  test_latency.py                   (C)
│  └─ test_icmp.py  test_route.py  test_output.py                  (D)
└─ results/                  실험 CSV, 그래프 이미지
```

**실행 모양 (main.py)**
```
sudo python3 -m src.main --target neverssl.com --dns-server google --network school-wifi --csv results/exp_a.csv
```

---

## 5. 역할 분배

| 담당 | 맡는 부분 | 파일 (본인만 수정) | 핵심 산출물 |
|---|---|---|---|
| **A — 캡처·통합** | F1 캡처 (AF_PACKET, OUT/IN 판별, 필터, 시각 기록) / Ethernet·IP 파싱 / `decode()` 합치기 / 전체 실행 흐름 / 실험 실행 스크립트 | `capture.py` `decode/link_ip.py` `decode/__init__.py` `main.py` `models.py` `experiments/run_*.sh` `domains.txt` | 패킷이 잡혀서 PacketInfo로 나오는 것 |
| **B — 전송 계층·연결 추적** | TCP·UDP 파싱 / **F3 접속 묶기** (DNS 응답 IP ↔ SYN 연결, 4개 묶음, HTTP·FIN 붙이기) | `decode/transport.py` `session.py` | Session 목록 |
| **C — 응용 계층·지연** | DNS 파싱 (이름 압축 포인터 포함) / HTTP 파싱 / **F4 단계별 지연** (Transaction ID 짝, 4개 묶음 짝) / 그래프 (평균·최대·표준편차, 단계 누적 막대) | `decode/app_dns.py` `decode/app_http.py` `latency.py` `experiments/plot.py` | LatencyResult, 그래프 |
| **D — 경로·출력** | ICMP 파싱 (안에 담긴 원본 IP·UDP 꺼내기) / **traceroute 경로 추적** (프로브 ↔ ICMP 짝, 홉별 지연) / **F5** 실시간 출력, 타임라인, CSV | `decode/icmp.py` `route.py` `output.py` | 홉별 지연, 화면 출력, CSV |

**이렇게 나눈 이유**
- 파일 하나에 주인이 한 명 → 같은 파일을 동시에 고칠 일이 없다.
- B는 TCP를 직접 파싱하므로 "4개 묶음으로 연결 추적"까지 맡는 게 자연스럽다.
- C는 DNS Transaction ID를 직접 파싱하므로 "DNS 질의↔응답 짝 맞추기"가 포함된 지연 측정과, 그 값을 정리하는 그래프까지 맡는다.
- D는 ICMP를 직접 파싱하므로 "ICMP 안 원본 포트로 traceroute 짝 맞추기"와 홉별 지연까지 한 흐름으로 맡는다. 경로 기능을 F3·F4에서 떼어내 B·C의 부담을 줄였다.
- A는 캡처가 가장 먼저 돌아가야 하므로 초반에 바쁘고, 후반에는 실행 흐름과 실험 실행 스크립트를 맡는다.
- 여러 사람이 손대고 싶어질 `main.py`와 `decode/__init__.py`는 뼈대 단계에서 모든 모듈을 미리 연결해 두었다 → 각자 자기 파일만 채우면 된다.

---

## 6. 의존 관계와 "기다리지 않는" 방법

```
A(F1, F2 하위) ─▶ B(TCP·UDP) · D(ICMP) · C(DNS·HTTP) ─▶ B(F3) · D(경로) ─▶ C(F4) ─▶ D(F5) ─▶ C(그래프)
```
흐름상으로는 앞사람이 끝나야 뒷사람이 돌릴 수 있지만, **2장의 데이터 약속 덕분에 모두 1일차부터 동시에 시작한다.**

| 담당 | 앞 단계가 없을 때 테스트하는 방법 |
|---|---|
| A | 실제 캡처로 바로 테스트 가능 |
| B (파싱) | Wireshark에서 TCP/UDP 계층을 `Copy → ...as a Hex Stream`으로 뽑은 샘플 |
| B (F3) | PacketInfo를 손으로 몇 개 만들어서 넣기 (DNS 응답 → SYN → SYN/ACK → GET → FIN 순서) |
| C (파싱) | Wireshark에서 DNS/HTTP 계층 hex 샘플 |
| C (F4) | Session을 손으로 만들어서 넣기 (ts만 정확히 넣으면 됨) |
| C (그래프) | 2.6 형식 CSV를 손으로 몇 줄 만들어서 넣기 |
| D (ICMP) | Wireshark에서 ICMP Time Exceeded 계층 hex 샘플 |
| D (경로) | UDP 프로브·ICMP 응답 PacketInfo를 손으로 만들어서 넣기 |
| D (출력) | LatencyResult를 손으로 만들어서 출력·CSV 확인 |
| A (실험 스크립트) | 처음부터 작성 가능 |

---

## 7. 개발 규칙 (GitHub)

- 저장소: 조직 `Wireshrimp-2026` 아래 `wireshrimp` 1개
- `main`은 항상 실행되는 상태 유지
- 각자 브랜치: A `feat/capture` `feat/experiments` / B `feat/transport` `feat/session` / C `feat/dns-http` `feat/latency` `feat/plot` / D `feat/icmp-route` `feat/output`
- **내 파일만 고치는 작은 수정** → 바로 push 가능 (push 전 `git pull` 필수)
- **단순 버그 수정, 주석·오타 수정** → PR 없이 `main`에 바로 push 가능 (push 전 `git pull` 필수)
- **새 기능, 큰 수정, 남의 파일, `models.py`, `main.py`** → PR, 한 명 이상 확인 후 merge
- 커밋 메시지: `[F3] SYN 4개 묶음 추적 추가` 처럼 기능 번호를 앞에

---

## 8. 일정 (오늘 11/10 기준)

| 날짜 | 할 일 | 담당 |
|---|---|---|
| ~11/13(금) 19:00 | **설계계획서 PPT 5장 제출** | 전원 |
| 11/14(토) | 저장소 생성, `models.py`·폴더·빈 파일 올리기 (= 뼈대 완성) | A |
| 11/14~19 | 각자 자기 파일 개발 + 샘플로 단위 테스트 | 전원 |
| 11/17(화) | 중간 점검: A의 캡처 + decode가 실제로 PacketInfo를 내놓는지 | A 주도 |
| 11/20~21 | 통합: 실제 `curl`, `dig`, `traceroute`로 끝까지 돌려보기 + Wireshark 비교 | 전원, A 주도 |
| 11/22~25 | 실험 A(DNS 서버 3종 × 30회), 실험 B(네트워크 3종 × 30회, traceroute 3회) + 그래프 | 전원 |
| ~11/27(금) 19:00 | **설계보고서 PPT 8장 + 소스 제출** | 전원 |

---

## 9. 완료 기준 (각자 체크)

- [ ] **A**: `sudo` 실행 시 `curl http://neverssl.com` 트래픽이 OUT/IN 구분되어 PacketInfo로 나온다. IP·TTL이 Wireshark와 일치한다. 실험 스크립트로 조건별 반복 실행 시 CSV가 쌓인다.

- [ ] **B**: Seq/Ack/Flags, UDP 포트·Length가 Wireshark와 일치한다. 접속 1회가 Session 1개로 묶이고, SYN·SYN/ACK·ACK·HTTP 요청·응답·FIN이 모두 붙는다.

- [ ] **C**: DNS 질의 도메인·응답 IP, HTTP 메서드·상태 코드가 Wireshark와 일치한다. dns_ms, tcp_connect_ms, http_first_byte_ms, total_ms가 계산된다. 조건별 평균·최대·표준편차 그래프와 단계 누적 막대 그래프가 나온다.

- [ ] **D**: ICMP Type·Code·원본 목적지 IP·포트가 Wireshark와 일치한다. traceroute 프로브와 ICMP 응답이 짝지어져 홉별 지연이 계산된다. 설계안 출력 예시 모양의 타임라인이 찍히고 CSV가 2.6 형식으로 쌓인다.
