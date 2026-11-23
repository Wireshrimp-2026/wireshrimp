# Raw Socket 기반 패킷 캡처·분석기 — 설계 및 역할 분배

> 기준: 「컴퓨터네트워크 설계 (2026학년도 2학기)」 과제 공지
> 역할은 **A, B** 두 개로 나눈다 (10장).
> 이 문서는 이전 설계(웹 접속 지연 측정·DNS 서버 비교 실험)를 대체한다. 이전 설계는 git 기록에 남아 있다.

---

## 0. 과제 요구사항과 대응

### 0.1 과제 원문 요약

| 구분 | 요구 내용 |
|---|---|
| 설계 내용 | 네트워크 상에서 전달되는 패킷을 캡처하고 분석. **송신과 수신을 모두 캡처** |
| 환경 | 유닉스(리눅스) 또는 윈도우 기반 **raw socket** 프로그램 |
| 캡처 데이터 | **APP 헤더, TCP(UDP) 헤더, IP 헤더** |
| 응용 프로토콜 (필수) | **HTTP, DNS** |
| 응용 프로토콜 (선택) | **e-mail (SMTP, POP 또는 IMAP), traceroute, P2P BitTorrent** |
| 세부 내용 | Application header / TCP: **연결설정·데이터 전송·연결해제 과정**, Source Port, Destination Port, Sequence No, Acknowledgement No 등 / UDP: Source Port, Destination Port 등 / IP: Source IP, Destination IP 등 |
| 제출 | 설계보고서 PPT 8쪽 (`design학생이름.ppt`: 목표, 설계 환경, 설계내용 및 결과, 기대효과) + **소스파일**, 11/27(금) 19:00, 팀별 1개 |

### 0.2 우리 대응 — 필수·선택 전부 구현

| 요구 | 구현 | 파일 | 확인 방법 |
|---|---|---|---|
| raw socket 캡처 | `AF_PACKET` + `SOCK_RAW`, `ETH_P_ALL` | `capture.py` | `sudo` 실행 |
| 송신·수신 모두 캡처 | `recvfrom()`의 pkttype으로 OUT/IN 구분 | `capture.py` | 출력에 OUT·IN 둘 다 |
| IP 헤더 | IPv4 헤더 전 필드 + 체크섬 검증 | `decode/link_ip.py` | Wireshark 비교 |
| TCP 헤더 | 전 필드 + 옵션(MSS, WS, SACK, TS) + 상대 Seq/Ack | `decode/transport.py` | Wireshark 비교 |
| UDP 헤더 | 전 필드 + 체크섬 검증 (의사 헤더 포함) | `decode/transport.py` | Wireshark 비교 |
| TCP 연결설정·전송·해제 | 연결별 상태 추적, 3-way / 데이터 / 4-way 요약 | `tcp_track.py` | 연결 요약 출력 |
| **HTTP (필수)** | 요청줄·상태줄·헤더 | `decode/app_http.py` | `curl` |
| **DNS (필수)** | 헤더·플래그·질의·응답 레코드 (UDP·TCP) | `decode/app_dns.py` | `dig` |
| SMTP (선택) | 명령·응답 코드·메일 헤더 | `decode/app_mail.py` | `curl smtp://` |
| POP3 (선택) | 명령·`+OK`/`-ERR` | `decode/app_mail.py` | `curl pop3://` |
| IMAP (선택) | 태그·명령·응답 | `decode/app_mail.py` | `curl imap://` |
| traceroute (선택) | UDP 프로브 ↔ ICMP 응답 짝, 홉 표 | `decode/icmp.py` `route.py` | `traceroute` |
| BitTorrent (선택) | 트래커 announce(HTTP+bencode), 피어 handshake·메시지, DHT | `decode/app_bt.py` | `transmission-cli` |
| 결과 확인 | 화면 출력 + 로그 파일 + **pcap 저장** (Wireshark로 열어 대조) | `output.py` `pcap.py` | Wireshark에서 열기 |

> 이전 설계에 있던 지연 측정(`latency.py`), 접속 묶기(`session.py`), DNS 서버·네트워크 비교 실험(`experiments/`), 그래프(`plot.py`)는 **과제 요구가 아니므로 제외**한다.

---

## 1. 환경

| 항목 | 내용 |
|---|---|
| 운영체제 | Ubuntu 22.04 이상 (윈도우 PC는 VirtualBox **브리지 모드**) |
| 언어 | Python 3 표준 라이브러리만 (`socket`, `struct`, `argparse`, `datetime`). **scapy, libpcap 사용 안 함** |
| 권한 | `sudo` (raw socket) |
| 분석 대상 | IPv4 (IPv6는 범위 밖, 트래픽 발생 시 `-4` 옵션 사용) |
| 검증 도구 | Wireshark (같은 시간에 함께 캡처하거나, 우리 프로그램이 저장한 pcap을 열어 비교) |
| 트래픽 발생 | `curl`, `dig`, `traceroute`, `transmission-cli`, 메일 테스트 서버(`tools/mail_server.py`) |

---

## 2. 전체 흐름

```
캡처(F1) ──▶ 계층별 해석(F2) ──▶ TCP 연결 추적(F3) ──▶ 출력·저장(F4)
Captured       PacketInfo            Connection              화면, 로그, pcap
                (Ethernet→IP→TCP/UDP/ICMP→응용)
```

| 단계 | 하는 일 |
|---|---|
| F1 캡처 | 인터페이스 하나에서 모든 프레임 수신, OUT/IN 판별, 커널 수신 시각 기록, 선택한 프로토콜만 남김 |
| F2 해석 | Ethernet → IPv4 → TCP/UDP/ICMP → 응용 계층 순으로 파싱. 응용 계층은 포트와 내용으로 판별 |
| F3 연결 추적 | TCP 연결마다 연결설정(SYN, SYN/ACK, ACK) → 데이터 전송 → 연결해제(FIN, ACK) 단계 기록, 상대 Seq/Ack 계산 |
| F4 출력·저장 | 패킷별 계층 출력, 연결 종료 시 연결 요약, traceroute 홉 표, 로그 파일·pcap 저장 |

---

## 3. 실행 방법

```bash
sudo python3 -m src.main --iface enp0s3 --proto http,dns
```

| 옵션 | 필수 | 설명 |
|---|---|---|
| `--iface` | O | 캡처할 인터페이스 (`ip -br link`로 확인) |
| `--proto` | | 분석할 프로토콜, 쉼표 구분. `http,dns,smtp,pop3,imap,traceroute,bittorrent,tls,all` (기본 `all`) |
| `--host` | | 이 IP와 주고받은 패킷만 (DNS 서버 등은 별도로 항상 허용) |
| `--port` | | 포트 재지정. 예: `smtp=2525,pop3=2110,imap=2143` |
| `--hex` | | 패킷마다 원본 바이트 hex 덤프도 출력 |
| `--log` | | 화면 출력을 파일에도 저장 (예: `results/http.txt`) |
| `--pcap` | | 캡처한 프레임을 pcap 파일로 저장 (예: `results/http.pcap`) |
| `--count` | | N개 패킷을 받으면 종료 (기본: `Ctrl+C`까지) |

### 3.1 프로토콜 판별 기준

판별은 `decode/app_select.py`의 `parse_app()`에서 한다.

| 프로토콜 | 전송 | 기본 포트 | 내용으로 판별 |
|---|---|---|---|
| HTTP | TCP | 80, 8080 | 첫 줄이 `GET`/`POST`/… 또는 `HTTP/1.` |
| DNS | UDP, TCP | 53 | — (TCP는 앞 2바이트 길이 제거) |
| SMTP | TCP | 25, 587 | — |
| POP3 | TCP | 110 | — |
| IMAP | TCP | 143 | — |
| traceroute | UDP + ICMP | UDP 33434~33534, ICMP Type 11·3 | ICMP 안 원본 UDP 목적지 포트 |
| BitTorrent 트래커 | TCP (HTTP) | 6969 등 | HTTP 요청 경로가 `/announce` |
| BitTorrent 피어 | TCP | 정해지지 않음 | 첫 데이터가 `\x13BitTorrent protocol` → 그 연결 전체를 BitTorrent로 표시 |
| BitTorrent DHT | UDP | 정해지지 않음 | 내용이 bencode 사전 `d1:` 로 시작하고 `y` 키가 있음 |
| TLS (참고) | TCP | 443, 465, 993, 995 | 암호화되어 해석하지 않음. `TLS record type=…`만 표시 |

---

## 4. 출력 형식

### 4.1 패킷별 출력

```
#12  14:03:11.123456  OUT  TCP  10.0.2.15:51234 -> 34.223.124.45:80  len=132
  [ETH ] dst=52:54:00:12:35:02 src=08:00:27:aa:bb:cc type=0x0800(IPv4)
  [IP  ] ver=4 hlen=20 tos=0x00 total=132 id=0x1c2d flags=DF frag=0 ttl=64 proto=6(TCP) cksum=0x8a1f(ok)
         src=10.0.2.15 dst=34.223.124.45
  [TCP ] sport=51234 dport=80 seq=1 ack=1 (raw seq=3021457731 ack=1874020011)
         hlen=32 flags=ACK,PSH win=502 cksum=0x4c2e urg=0 opts=[NOP, NOP, TS val=… ecr=…]
  [HTTP] GET / HTTP/1.1
         Host: neverssl.com
         User-Agent: curl/8.5.0
         Accept: */*
```

- 맨 윗줄: 번호, 시각, **방향(OUT/IN)**, 전송 프로토콜, 주소:포트, 프레임 길이
- 응용 계층을 판별하지 못한 데이터는 `[DATA] 78 bytes` + 앞 32바이트 hex
- 비밀번호(POP3 `PASS`, IMAP `LOGIN`, SMTP `AUTH`)는 `****`로 가려서 출력

### 4.2 TCP 연결 요약 (연결이 끝나거나 프로그램 종료 시)

```
[CONN] 10.0.2.15:51234 <-> 34.223.124.45:80  (HTTP)
  연결설정  #10 OUT SYN      seq=0
            #11 IN  ACK,SYN  seq=0 ack=1
            #12 OUT ACK      seq=1 ack=1          (3-way handshake 완료)
  데이터    OUT 1개 세그먼트 78 bytes / IN 4개 세그먼트 4,321 bytes
  연결해제  #20 OUT ACK,FIN  seq=79 ack=4322
            #21 IN  ACK,FIN  seq=4322 ack=80
            #22 OUT ACK      seq=80 ack=4323      (정상 종료)
```

- RST로 끝나면 연결해제에 RST 세그먼트와 `(RST, 비정상 종료)`
- 캡처 시작 전에 열린 연결은 `연결설정  (캡처 전에 열림)`

### 4.3 traceroute 홉 표 (traceroute 패킷이 있었을 때, 종료 시)

```
[ROUTE] -> 34.223.124.45
  hop  router            rtt1     rtt2     rtt3     ICMP
    1  10.0.2.2          0.4 ms   0.3 ms   0.3 ms   11/0 Time Exceeded
    2  192.168.0.1       2.1 ms   2.0 ms   2.3 ms   11/0 Time Exceeded
    3  *                 *        *        *        (응답 없음)
   12  34.223.124.45    151.0 ms 150.2 ms 150.8 ms  3/3 Port Unreachable (도착)
```

---

## 5. 데이터 약속 (`src/models.py`)

모든 형식은 `src/models.py` 한 파일에만 둔다. **팀 합의 없이 고치지 않는다.** (PR + 단톡방 공지)

### 5.1 Captured — F1 → F2
| 필드 | 타입 | 설명 |
|---|---|---|
| `no` | int | 캡처 순번 (1부터) |
| `ts` | float | 커널 수신 시각 (초) |
| `direction` | str | `"OUT"` / `"IN"` |
| `frame` | bytes | 이더넷 헤더부터 프레임 전체 |

### 5.2 PacketInfo — F2 → F3·F4
| 필드 | 타입 | 채우는 곳 | 설명 |
|---|---|---|---|
| `no`, `ts`, `direction`, `frame_len` | | Captured | Captured에서 |
| `eth` | dict | `link_ip.py` | `src_mac`, `dst_mac`, `ethertype`, `vlan` |
| `ip` | dict \| None | `link_ip.py` | `version`, `header_len`, `tos`, `total_length`, `id`, `df`, `mf`, `frag_offset`, `ttl`, `protocol`, `checksum`, `checksum_ok`, `src_ip`, `dst_ip` |
| `proto` | str | `link_ip.py` | `"TCP"` / `"UDP"` / `"ICMP"` / `"OTHER"` |
| `tcp` | dict \| None | `transport.py` | `src_port`, `dst_port`, `seq`, `ack`, `header_len`, `flags`(문자열), `flag_bits`(int), `window`, `checksum`, `urgent`, `options`(list[str]) |
| `udp` | dict \| None | `transport.py` | `src_port`, `dst_port`, `length`, `checksum`, `checksum_ok`, `checksum_partial` |
| `icmp` | dict \| None | `icmp.py` | `type`, `code`, `type_name`, `checksum`, (Echo) `id`, `seq`, (오류 메시지) `orig_src_ip`, `orig_dst_ip`, `orig_proto`, `orig_src_port`, `orig_dst_port`, `orig_ttl`, (원본이 ICMP Echo, `traceroute -I`) `orig_id`, `orig_seq` |
| `payload` | bytes | `transport.py` | 전송 계층 헤더를 뗀 데이터 |
| `app` | AppInfo \| None | `app_*.py` | 응용 계층 해석 결과 |
| `rel_seq`, `rel_ack` | int \| None | `tcp_track.py` | F3에서 채움 (연결 시작 기준 상대값) |
| `frame` | bytes | Captured | 원본 프레임 (`--hex` 덤프용) |

- `tcp_flags` 문자열 순서는 Wireshark와 같게 고정: `CWR,ECE,URG,ACK,PSH,RST,SYN,FIN` 중 켜진 것만. 예: `"SYN,ACK"`는 `"ACK,SYN"`으로 쓴다.

### 5.3 AppInfo — 응용 계층 공통 형식
| 필드 | 타입 | 설명 |
|---|---|---|
| `name` | str | `"HTTP"`, `"DNS"`, `"SMTP"`, `"POP3"`, `"IMAP"`, `"BT-TRACKER"`, `"BT-PEER"`, `"BT-DHT"`, `"TLS"` |
| `summary` | str | 한 줄 요약. 예: `GET / HTTP/1.1`, `Standard query 0x1a2b A neverssl.com` |
| `lines` | list[str] | 출력할 세부 줄 (헤더 이름: 값). 출력은 이 목록을 그대로 찍는다 |
| `fields` | dict | 다른 모듈이 쓸 값 (예: DNS `txid`, `is_response`, `answers` / HTTP `method`, `status_code`) |

> 응용 프로토콜마다 형식을 따로 만들지 않고 이 하나로 통일한다. 출력 담당은 `name`, `summary`, `lines`만 보면 된다.

### 5.4 Connection — F3 (TCP 연결 1개)
| 필드 | 타입 | 설명 |
|---|---|---|
| `key` | (str, int, str, int) | (클라이언트 IP, 포트, 서버 IP, 포트) — SYN 보낸 쪽이 클라이언트 |
| `app_name` | str \| None | 연결에서 처음 판별된 응용 프로토콜 |
| `isn_client`, `isn_server` | int \| None | 초기 Seq (상대값 계산용) |
| `handshake` | list[PacketInfo] | SYN, SYN/ACK, ACK |
| `data_count`, `data_bytes` | dict | 방향별 `{"OUT": n, "IN": n}` |
| `teardown` | list[PacketInfo] | FIN 교환과 마지막 ACK, 또는 RST |
| `state` | str | `SYN_SENT` → `SYN_RCVD` → `ESTABLISHED` → `FIN_WAIT` → `CLOSED` / `RESET` |

### 5.5 Hop — traceroute
`(홉 번호, 라우터 IP 또는 None, [rtt ms 또는 None, ...], ICMP type/code 문자열)`

> 값을 알 수 없으면 **0이 아니라 None**.

---

## 6. 함수 약속 (파일별 공개 함수)

> 도우미 함수는 자유롭게 추가. **아래 공개 함수의 이름·입력·출력만 바꾸지 않는다.**

| 파일 | 공개 함수 | 입력 → 출력 |
|---|---|---|
| `capture.py` | `capture(filter)` | `CaptureFilter` → `Captured` 제너레이터 |
| `capture.py` | `CaptureFilter` | 인터페이스, 프로토콜 목록, 포트 표, 대상 IP |
| `decode/link_ip.py` | `parse_ethernet(frame)` | bytes → (dict, EtherType, 나머지) |
| `decode/link_ip.py` | `parse_ip(data)` | bytes → (dict, 나머지) |
| `decode/transport.py` | `parse_tcp(data)` / `parse_udp(data, src_ip, dst_ip)` | bytes → (dict, 페이로드). UDP는 IP 주소로 의사 헤더를 만들어 체크섬을 검증 |
| `decode/icmp.py` | `parse_icmp(data)` | bytes → dict (오류 메시지면 안쪽 IP·UDP 포함) |
| `decode/app_select.py` | `parse_app(conn_key, proto, src_port, dst_port, payload, ports)` | 응용 계층 진입점. 3.1 표로 프로토콜을 판별해 아래 파서 중 하나를 부름 → AppInfo 또는 None. `conn_key`는 `models.canonical_key()`로 만든 방향 무관 키. 메일 파서의 `from_client`는 이 함수가 포트로 정한다 |
| `decode/app_dns.py` | `parse_dns(data, over_tcp)` | bytes → AppInfo. `over_tcp`면 앞 2바이트 길이를 이 함수가 뗌 |
| `decode/app_http.py` | `parse_http(data)` | bytes → AppInfo 또는 None (HTTP 첫 줄이 아님) |
| `decode/app_bt.py` | `parse_bt_peer(conn_key, data)` / `parse_bt_tracker(data)` / `parse_bt_dht(data)` | bytes → AppInfo 또는 None. 트래커는 HTTP 파서를 거치지 않고 직접 해석, 피어 메시지 경계는 이 파일 안에서 `conn_key`별로 기억 |
| `decode/app_mail.py` | `parse_smtp(conn_key, data, from_client)` / `parse_pop3(...)` / `parse_imap(...)` | bytes → AppInfo. `STARTTLS` 이후 여부는 이 파일 안에서 `conn_key`별로 기억 |
| `decode/app_tls.py` | `parse_tls(data)` | bytes → AppInfo (레코드 헤더만) |
| `decode/__init__.py` | `decode(captured, ports)` | Captured → PacketInfo 또는 None. Ethernet → IP → TCP/UDP/ICMP를 차례로 호출하고, 응용 계층은 `parse_app()`에 넘김 |
| `tcp_track.py` | `TcpTracker.add(pkt)` → 끝난 `Connection` 또는 None / `.remaining()` | PacketInfo를 하나씩 받아 상대 Seq 채우고 연결 상태 갱신 |
| `route.py` | `RouteTracker.add(pkt)` / `.hops()` | 프로브 ↔ ICMP 짝 → 목적지별 `[Hop]` |
| `output.py` | `open_log(path)` / `close_log()` / `print_packet(pkt, hex=False)` / `print_connection(conn)` / `print_route(dst, hops)` | 4장 형식으로 출력 (`open_log` 후에는 로그 파일 동시 기록) |
| `pcap.py` | `PcapWriter(path).write(captured)` / `.close()` | pcap 파일 저장 (전역 헤더 24B + 레코드 헤더 16B, linktype 1) |

**연결 순서 (`main.py`)**
```
for captured in capture(filter):
    pcap.write(captured)
    pkt = decode(captured, ports)
    if pkt is None: continue
    conn = tcp.add(pkt)        # 상대 Seq 채움, 끝난 연결이면 반환
    route.add(pkt)
    print_packet(pkt)
    if conn: print_connection(conn)
종료 시: 남은 연결 print_connection, route.hops() → print_route
```

**에러 처리 약속**
- 파서(`parse_*`)는 데이터가 짧거나 깨졌으면 `ValueError`.
- `decode()`는 하위 파서 예외를 잡아 해당 계층만 None으로 두고 계속 진행 (현재 코드 그대로).

---

## 7. 프로토콜별 세부 설계

### 7.1 IP 헤더
- Version, IHL, TOS, Total Length, Identification, Flags(DF·MF), Fragment Offset, TTL, Protocol, Header Checksum, Source IP, Destination IP
- 체크섬을 직접 다시 계산해 `ok` / `bad` 표시 (송신 패킷은 NIC 오프로드로 0일 수 있음 → `offload`로 표시)
- 조각난 패킷의 두 번째 조각부터는 전송 계층 해석 안 함

### 7.2 TCP·UDP 헤더
- TCP: Source Port, Destination Port, **Sequence No, Acknowledgement No**, Data Offset, Flags 9비트, Window, Checksum, Urgent Pointer, Options(MSS, Window Scale, SACK Permitted, SACK, Timestamps, NOP, EOL)
- UDP: Source Port, Destination Port, Length, Checksum
- **UDP 체크섬은 반드시 검증한다**: 의사 헤더(출발지 IP 4B, 목적지 IP 4B, 0 1B, Protocol 17 1B, UDP Length 2B) + UDP 헤더(체크섬 칸은 그대로) + 데이터를 16비트 1의 보수로 더해 0이면 `checksum_ok=True`, 아니면 `False`
  - 체크섬 값이 0이면 송신 측이 체크섬을 쓰지 않은 것(IPv4에서 허용) → `checksum_ok=None`
  - 데이터가 UDP Length보다 짧게 잡혀(IP 조각 등) 검증할 수 없을 때도 → `checksum_ok=None`
  - 체크섬을 랜카드가 나중에 채우는 경우(checksum offload) 캡처한 체크섬 칸에는 의사 헤더 합만 들어 있다 → 틀렸지만 이 값과 같으면 `checksum_partial=True`, 출력에서 `offload`로 표시 (보내는 패킷, 그리고 가상 랜카드·VM에서는 받는 패킷에도 생김)
  - 출력: `ok` / `bad` / `offload` / `unused`(체크섬 0) / `unchecked`(잘려서 검증 불가)

### 7.3 TCP 연결 추적 (`tcp_track.py`)
| 단계 | 판단 |
|---|---|
| 연결설정 | SYN(OUT 또는 IN) → 반대 방향 SYN,ACK → 처음 SYN 보낸 쪽의 ACK. 이때 양쪽 ISN 저장 |
| 데이터 전송 | `payload`가 있는 세그먼트. 방향별 개수·바이트 누적. 재전송(이미 받은 구간이 다시 등장)은 `재전송`으로 따로 셈. 순서가 바뀌어 늦게 온 세그먼트는 재전송이 아니고, keep-alive(1바이트)는 세지 않음 |
| 연결해제 | FIN 한쪽 → ACK → 반대쪽 FIN → ACK (FIN,ACK가 겹쳐 3개로 끝나는 경우도 정상) |
| 비정상 종료 | RST |
| 상대 Seq/Ack | `seq - ISN`, `ack - 상대 ISN` (Wireshark "relative sequence number"와 같은 값) |

### 7.4 DNS — 필수
- 헤더: ID, Flags(QR, Opcode, AA, TC, RD, RA, Z, RCODE), QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
- Question: 이름, Type, Class
- Answer/Authority/Additional: 이름, Type, Class, TTL, RDLENGTH, RDATA (A, AAAA, CNAME, NS, MX, PTR, TXT, SOA 표시. 그 밖은 hex)
- **이름 압축 포인터(0xC0)** 처리, 포인터 무한 반복 방지
- DNS over TCP(`dig +tcp`): 앞 2바이트 길이 제거
- 요약: Wireshark Info 칸과 같은 모양 — `Standard query 0x1a2b A neverssl.com` / `Standard query response 0x1a2b A neverssl.com A 34.223.124.45` / 오류면 `… response 0x1a2b No such name A nx.example.com SOA a.iana-servers.net`
- Flags의 Z·AD·CD는 Wireshark처럼 1비트씩 따로 표시 (dig는 질의에 AD를 켠다), EDNS OPT 레코드(dig가 늘 붙임)는 UDP 크기·DO 비트·옵션 이름으로 표시

### 7.5 HTTP — 필수
- 요청: Method, Request-URI, Version, 헤더 전체 (`Host`, `User-Agent`, `Accept`, `Connection` …)
- 응답: Version, Status Code, Reason Phrase, 헤더 전체 (`Content-Type`, `Content-Length`, `Server` …)
- 헤더 끝(`\r\n\r\n`) 뒤의 본문은 `body: N bytes`만 표시
- 첫 줄이 HTTP가 아닌 세그먼트(응답 본문 이어짐)는 `[HTTP] continuation N bytes`

### 7.6 SMTP · POP3 · IMAP — 선택 e-mail
| 프로토콜 | 클라이언트 → 서버 | 서버 → 클라이언트 |
|---|---|---|
| SMTP | `EHLO`/`HELO`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`, `STARTTLS`, `AUTH` | 3자리 응답 코드 + 문구 (`220`, `250`, `354`, `221`), 여러 줄 응답(`250-`) |
| SMTP DATA | 메일 헤더(`From`, `To`, `Subject`, `Date`)와 본문 길이 | — |
| POP3 | `USER`, `PASS`, `STAT`, `LIST`, `RETR`, `DELE`, `QUIT` | `+OK` / `-ERR` + 문구, `RETR` 응답은 메일 헤더 표시 |
| IMAP | 태그 + 명령 (`a1 LOGIN`, `a2 SELECT INBOX`, `a3 FETCH 1 BODY[]`, `a4 LOGOUT`) | 태그 없는 응답(`* 3 EXISTS`), 태그 응답(`a2 OK`/`NO`/`BAD`) |
- 한 세그먼트에 여러 줄이 오면 줄마다 해석
- `STARTTLS` 이후 데이터는 `TLS (암호화 시작)`으로 표시하고 해석 중단 (연결별 상태는 `app_mail.py` 안에서 `conn_key`로 기억)
- 비밀번호는 `****`

### 7.7 traceroute — 선택
- 프로브: UDP, 목적지 포트 33434부터 증가, TTL 1부터 증가 → IP 헤더의 TTL로 홉 번호
- 응답: ICMP Type 11 Code 0(Time Exceeded) → 중간 라우터 / Type 3 Code 3(Port Unreachable) → 목적지 도착
- 짝 맞추기: ICMP 안에 담긴 **원본 IP 헤더 + UDP 앞 8바이트**에서 목적지 IP·포트를 꺼내 프로브와 비교
- RTT = ICMP 수신 시각 − 프로브 송신 시각
- `traceroute -I`(ICMP Echo 방식)도 지원: Echo Request(8)의 id·seq ↔ Echo Reply(0) 또는 Time Exceeded 안의 원본 ICMP id·seq

### 7.8 BitTorrent — 선택
| 부분 | 해석 내용 |
|---|---|
| 트래커 요청 (HTTP GET `/announce?…`) | `info_hash`(URL 디코딩 → 40자리 hex), `peer_id`, `port`, `uploaded`, `downloaded`, `left`, `event`, `compact` |
| 트래커 응답 (bencode) | `interval`, `complete`, `incomplete`, `peers` (compact 6바이트 → `IP:port` 목록) |
| 피어 handshake | pstrlen(19), pstr(`BitTorrent protocol`), reserved 8바이트(확장 비트), info_hash, peer_id |
| 피어 메시지 | 4바이트 길이 + ID: keep-alive, choke(0), unchoke(1), interested(2), not interested(3), have(4) piece, bitfield(5) 길이, request(6) index·begin·length, piece(7) index·begin·블록 크기, cancel(8), extended(20) |
| 메시지 경계 | piece 메시지는 여러 세그먼트에 걸침 → `app_bt.py` 안에 연결(`conn_key`)별 "남은 바이트"를 기억해 다음 메시지 시작 위치를 찾음 |
| 트래커·피어 판별 | `parse_app()`이 `parse_bt_tracker()`를 먼저 부르고, None이면 `parse_http()`로 넘김. 피어 handshake 시그니처 확인도 `parse_app()` 안에서 함. 트래커 요청줄·bencode 응답은 `app_bt.py`가 직접 해석 |
| DHT (UDP, KRPC) | bencode 해석: `t`(트랜잭션), `y`(q/r/e), `q`(ping, find_node, get_peers, announce_peer) |
- bencode 해석기는 직접 작성 (정수 `i…e`, 문자열 `길이:값`, 리스트 `l…e`, 사전 `d…e`)
- 트래픽 발생 시 **암호화 끔** (`transmission-cli -et`) — 켜져 있으면 handshake가 보이지 않음

### 7.9 TLS (참고)
- 443/465/993/995: TLS 레코드 헤더(Content Type, Version, Length)만 표시. 내용은 해석하지 않음.

---

## 8. 트래픽 발생과 시연 절차

분석기를 한 터미널에서 띄우고, 다른 터미널에서 아래를 실행한다. 프로토콜마다 결과를 `--log`·`--pcap`으로 저장해 보고서에 쓴다.

| 프로토콜 | 분석기 | 트래픽 발생 |
|---|---|---|
| HTTP + DNS | `--proto http,dns --log results/http.txt --pcap results/http.pcap` | `curl -4 http://neverssl.com` |
| DNS (UDP) | `--proto dns` | `dig @8.8.8.8 example.com A` / `dig @8.8.8.8 gmail.com MX` |
| DNS (TCP) | `--proto dns` | `dig +tcp @8.8.8.8 example.com` |
| SMTP | `--proto smtp --host 서버IP` | `curl smtp://서버IP:25 --mail-from a@test.local --mail-rcpt b@test.local -T mail.txt` |
| POP3 | `--proto pop3 --host 서버IP` | `curl pop3://서버IP/1 -u user:pass` |
| IMAP | `--proto imap --host 서버IP` | `curl "imap://서버IP/INBOX;UID=1" -u user:pass` |
| SMTP (실제 서버) | `--proto smtp` | `curl -v smtp://smtp.gmail.com:587` → `EHLO`·`STARTTLS`까지 평문 확인 |
| traceroute (UDP) | `--proto traceroute` | `traceroute -4 -q 3 neverssl.com` |
| traceroute (ICMP) | `--proto traceroute` | `sudo traceroute -4 -I neverssl.com` |
| BitTorrent | `--proto bittorrent --pcap results/bt.pcap` | `transmission-cli -et -w /tmp/bt ubuntu-24.04-desktop-amd64.iso.torrent` (Ubuntu 공식 torrent, 1~2분 후 종료) |

**메일 테스트 서버** (`tools/mail_server.py`)
- 실제 메일 서버는 대부분 암호화(993, 995, STARTTLS)라 명령이 안 보이므로, **평문 SMTP·POP3·IMAP을 흉내 내는 간단한 서버**를 직접 만든다 (`socket` + `threading`, 미리 넣어 둔 메일 1통, 계정 `user`/`pass`).
- 분석기를 돌리는 PC가 아닌 **다른 PC**(호스트 윈도우, 팀원 노트북)에서 실행한다. 같은 PC에서 돌리면 `lo`로만 오가서 인터페이스 캡처에 잡히지 않는다.
- 포트 25/110/143을 쓰면 `sudo` 필요. 권한이 없으면 2525/2110/2143으로 띄우고 분석기에 `--port smtp=2525,pop3=2110,imap=2143`.

**Wireshark 대조**
- 저장한 `results/*.pcap`을 Wireshark로 열어, 같은 번호의 패킷에서 IP·TCP·UDP·응용 필드가 우리 출력과 같은지 확인한다.
- 프로토콜마다 대조 화면 캡처 1장씩 → 보고서 "설계내용 및 결과"에 사용.

---

## 9. 폴더 구조

```
wireshrimp/
├─ README.md
├─ .github/workflows/tests.yml     CI (PR·main push마다 문법 검사·단위 테스트, 파이썬 3.10·3.12)
├─ docs/DESIGN.md                  이 문서
├─ src/
│  ├─ main.py                      실행 시작점, 옵션, 전체 연결
│  ├─ models.py                    데이터 형식 (수정은 팀 합의)
│  ├─ capture.py                   F1 캡처
│  ├─ pcap.py                      pcap 저장
│  ├─ output.py                    F4 화면·로그 출력
│  ├─ tcp_track.py                 F3 TCP 연결 추적
│  ├─ route.py                     traceroute 홉 표
│  └─ decode/
│     ├─ __init__.py               decode(): 계층 파서 합치기
│     ├─ link_ip.py                Ethernet, IPv4
│     ├─ app_select.py             parse_app(): 응용 프로토콜 판별
│     ├─ app_tls.py                TLS 레코드 헤더
│     ├─ transport.py              TCP, UDP
│     ├─ icmp.py                   ICMP
│     ├─ app_dns.py                DNS
│     ├─ app_http.py               HTTP
│     ├─ app_bt.py                 BitTorrent (트래커, 피어, DHT, bencode)
│     └─ app_mail.py               SMTP, POP3, IMAP
├─ tools/
│  └─ mail_server.py               평문 메일 테스트 서버
├─ tests/
│  ├─ samples/                     Wireshark에서 뽑은 hex 샘플
│  ├─ test_link_ip.py  test_capture.py  test_pcap.py  test_output.py
│  ├─ test_transport.py  test_tcp_track.py  test_http.py
│  ├─ test_dns.py  test_bt.py
│  └─ test_icmp.py  test_route.py  test_mail.py
└─ results/                        로그, pcap, 대조 화면 캡처
```

### 9.1 기존 코드 정리

| 파일 | 처리 |
|---|---|
| `capture.py` | **유지.** `CaptureFilter`를 프로토콜 목록·포트 표 기준으로 바꾸고 `no`(순번) 추가 |
| `decode/link_ip.py` | **유지.** IP 체크섬 검증 추가 |
| `decode/__init__.py` | **유지.** 응용 계층은 `parse_app()` 한 번 호출로 바꿈 (DNS TCP 길이 떼기도 여기서 빼서 `parse_dns`로), dict 그대로 담기 |
| `models.py` | **다시 작성** (5장) |
| `main.py` | **다시 작성** (3장 옵션, 6장 연결 순서) |
| `decode/transport.py` `icmp.py` `app_dns.py` `app_http.py` `route.py` `output.py` | 새 약속에 맞춰 구현 |
| `session.py` `latency.py` `experiments/` 전체 | **삭제** (과제 범위 밖) |
| `tests/test_session.py` `test_latency.py` | **삭제**, 대신 `test_tcp_track.py` |

---

## 10. 역할 분배

| 담당 | 맡는 부분 | 파일 (본인만 수정) |
|---|---|---|
| **A** — 패킷·연결·출력 | Ethernet·IPv4 헤더(체크섬 검증), TCP 헤더(옵션 포함)·UDP 헤더(체크섬 검증), TCP 연결 추적(연결설정·데이터·해제, 상대 Seq/Ack, 재전송, RST), `decode()` 합치기, 실행 흐름·옵션, 화면·로그 출력(4장 형식 전부), pcap 저장 | `decode/link_ip.py` `decode/transport.py` `decode/__init__.py` `tcp_track.py` `main.py` `models.py` `output.py` `pcap.py` |
| **B** — 응용 프로토콜·traceroute | 응용 프로토콜 판별(`parse_app()`), HTTP 요청·응답, DNS(헤더·플래그·레코드, 이름 압축, TCP DNS 길이 처리), SMTP·POP3·IMAP(명령·응답, STARTTLS 이후 중단, 비밀번호 가림), bencode 해석기, BitTorrent 트래커·피어 handshake·메시지·DHT, TLS 레코드 헤더, ICMP(Echo, 오류 메시지 안쪽 IP·UDP), traceroute 프로브 짝 맞추기·홉 표(UDP·ICMP 방식) | `decode/app_select.py` `decode/app_http.py` `decode/app_dns.py` `decode/app_mail.py` `decode/app_bt.py` `decode/app_tls.py` `decode/icmp.py` `route.py` |

**이렇게 나눈 이유**
- A는 바이트를 받아 IP·TCP·UDP를 풀고 연결을 추적해 화면에 찍는 쪽, B는 과제 공지의 응용 프로토콜(HTTP, DNS, 메일, traceroute, BitTorrent)을 해석하는 쪽.
- traceroute는 과제 공지에서 응용 프로토콜 목록에 들어 있고, ICMP 파서도 `bytes → dict` 독립 함수라 B가 맡는다.
- 응용 프로토콜 판별, DNS TCP 길이 처리, 메일·BitTorrent의 연결별 상태를 모두 B의 파일 안에 둬서, A의 `decode()`는 `parse_app()`과 `parse_icmp()` 두 함수만 부른다.
- 분량: A는 TCP 연결 추적과 출력 3종이 크고, B는 BitTorrent와 traceroute가 크다. 남은 일 기준으로 비슷하게 맞췄다.

**역할 사이에 겹치는 곳**

서로 상대 파일을 고치지 않고, 아래 약속만 맞춘다.

| 맞닿는 곳 | 약속 |
|---|---|
| A의 `decode()`가 B를 부름 | `parse_app()`, `parse_icmp()`의 이름·입력·출력 (6장) |
| A의 `main.py`가 B의 traceroute를 부름 | `RouteTracker.add(pkt)` / `.hops()`, Hop 형식 (5.5) |
| B의 traceroute가 A의 결과를 읽음 | `pkt.ip`의 `ttl`·`src_ip`·`dst_ip`, `pkt.udp`의 `dst_port` 키만 읽음 (5.2) |
| A의 출력이 B의 결과를 찍음 | AppInfo의 `name`·`summary`·`lines` (5.3), `pkt.icmp` 키 (5.2) |
| A의 연결 요약에 응용 이름 표시 | `pkt.app.name`만 읽음 |

### 10.1 완료 기준

- [ ] **A**: IP·TCP(옵션 포함)·UDP 헤더 전 필드와 IP·UDP 체크섬 검증 결과, 상대 Seq/Ack가 출력된다. `curl` 1회가 4.2 형식 연결 요약 1개로 나온다 (연결설정 3개, 데이터, 연결해제). 4.1·4.2·4.3 형식이 모두 찍히고 로그 파일에도 같은 내용이 남는다. 캡처한 프레임이 pcap 형식으로 저장된다.
- [ ] **B**: `parse_app()`이 3.1 표대로 프로토콜을 고른다. HTTP 요청줄·상태줄·헤더가 출력된다. DNS 헤더·플래그·질의·응답(A, AAAA, CNAME, MX)이 UDP·TCP 모두 출력된다. SMTP·POP3·IMAP 명령·응답이 출력되고 비밀번호가 가려진다. BitTorrent handshake의 info_hash·peer_id, 트래커 요청 인자와 응답의 peers 목록, 피어 메시지 종류, DHT 질의 종류가 출력된다. ICMP Type·Code와 안쪽 원본 IP·포트가 나오고, traceroute(UDP·ICMP 방식)가 홉 목록으로 나온다.

### 10.2 공통 약속
- 데이터 형식은 `src/models.py`에만. 팀 합의 없이 고치지 않는다.
- 공개 함수의 이름·입력·출력은 바꾸지 않는다.
- 파서는 깨진 데이터에 `ValueError`. 알 수 없는 값은 None.
---

## 11. 개발 규칙 (GitHub)

| 규칙 | 내용 |
|---|---|
| 저장소 | 조직 `Wireshrimp-2026` 아래 `wireshrimp` |
| `main` | 항상 실행되는 상태 유지 |
| 브랜치 | A `feat/packet` `feat/output` · B `feat/app` `feat/route` |
| PR 필요 | 새 기능, 남의 파일, `models.py`, `main.py` → 다른 한 명이 확인 후 merge |
| 바로 push | 내 파일의 작은 수정, 오타 (push 전 `git pull`) |
| 커밋 메시지 | `[F3] FIN 교환 추적 추가`, `[DNS] MX 레코드 해석` 처럼 앞에 기능·프로토콜, 끝에 issue 번호 `(#12)` |
| CI | PR·`main` push마다 GitHub Actions(`.github/workflows/tests.yml`)가 문법 검사·모듈 불러오기·단위 테스트를 돌린다. ✗가 뜨면 고친 뒤 merge |

### 11.1 Issue 규칙 — 역할별로 만든다

- **작업을 시작하기 전에 자기 역할의 issue를 먼저 만든다.** issue 하나 = 작업 하나.
- 제목 앞에 역할을 붙인다: `[A] UDP 체크섬 검증`, `[B] DNS 이름 압축 포인터 처리`
- 라벨: `role:A` 또는 `role:B` (+ 필요하면 `bug`). Assignee는 그 역할을 맡은 사람.
- 본문에 적을 것: 할 일, 고칠 파일, 완료 기준 (10.1에서 해당 부분)
- PR 본문에 `Closes #번호`를 적어 merge되면 issue가 자동으로 닫히게 한다.
- **다른 역할의 파일에 고칠 점이 생기면 직접 고치지 않고**, 그 역할 라벨로 issue를 만들어 넘긴다.
- `models.py`나 함수 약속(6장)을 바꿔야 하면 `role:A`·`role:B` 둘 다 붙인 issue로 먼저 합의한다.

처음 만들 issue (역할별):

| 역할 | issue |
|---|---|
| A | `[A] TCP·UDP 헤더 파싱 (UDP 체크섬 검증 포함)` · `[A] TCP 연결 추적` · `[A] 패킷·연결·홉 표 출력과 로그` · `[A] pcap 저장` |
| B | `[B] 응용 프로토콜 판별 parse_app` · `[B] HTTP` · `[B] DNS` · `[B] SMTP·POP3·IMAP` · `[B] BitTorrent` · `[B] TLS 레코드 헤더` · `[B] ICMP·traceroute` |

---

## 12. 일정 (11/21 기준, 마감 11/27(금) 19:00)

| 날짜 | 할 일 |
|---|---|
| 11/21(토) | 이 문서 확정, `models.py`·`main.py` 새 약속으로 교체, 기존 범위 밖 파일 삭제 |
| 11/21~23 | 파서 구현 + hex 샘플 단위 테스트 |
| 11/23(월) | 중간 점검: HTTP·DNS가 처음부터 끝까지 출력되는지 (필수 먼저) |
| 11/24(화) | 선택 기능 마무리: 메일, traceroute, BitTorrent |
| 11/25(수) | 통합 시연: 8장 표 순서대로 전부 실행, 로그·pcap 저장, Wireshark 대조 화면 캡처 |
| 11/26(목) | 설계보고서 PPT 8쪽 작성 (아래 13장), 소스 정리 |
| 11/27(금) 19:00 | **`design학생이름.ppt` + 소스파일 eclass 업로드** (팀 1개) |

---

## 13. 설계보고서 PPT 8쪽 구성

| 쪽 | 제목 | 내용 |
|---|---|---|
| 1 | 목표 | raw socket으로 송수신 패킷 캡처, IP·TCP/UDP·응용 헤더 분석. 필수(HTTP, DNS) + 선택(SMTP·POP3·IMAP, traceroute, BitTorrent) 전부 |
| 2 | 설계 환경 | Ubuntu, Python 3 표준 라이브러리, AF_PACKET, sudo, Wireshark 검증, 트래픽 발생 도구 |
| 3 | 설계 내용 ① 구조 | 2장 흐름도, 모듈·담당 표, OUT/IN 판별 방법 |
| 4 | 설계 내용 ② IP·TCP·UDP | 헤더 해석 필드, TCP 연결설정·전송·해제 추적 방법 |
| 5 | 결과 ① HTTP·DNS | 출력 화면 + Wireshark 대조, TCP 연결 요약 |
| 6 | 결과 ② e-mail | SMTP·POP3·IMAP 출력 화면 + Wireshark 대조 |
| 7 | 결과 ③ traceroute·BitTorrent | 홉 표 vs `traceroute` 출력, BitTorrent handshake·트래커 응답 |
| 8 | 기대효과 | 계층별 헤더 구조 이해, TCP 상태 변화 확인, Wireshark 없이 직접 분석, 한계(IPv6·TLS 내용 미해석) |
