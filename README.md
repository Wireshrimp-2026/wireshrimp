# wireshrimp

**Raw Socket 기반 패킷 캡처·분석기**

내 PC가 보내고 받는 패킷을 raw socket으로 직접 잡아 **IP · TCP/UDP · 응용 계층 헤더**를 계층별로 보여 줍니다. TCP는 연결설정 → 데이터 전송 → 연결해제 과정을 연결마다 요약합니다.

> 컴퓨터네트워크설계 팀 프로젝트 · 자세한 설계는 [docs/DESIGN.md](docs/DESIGN.md)

| 구분 | 프로토콜 |
|---|---|
| 필수 | HTTP, DNS |
| 선택 | SMTP · POP3 · IMAP, traceroute, BitTorrent |
| 헤더 | Ethernet, IPv4, TCP, UDP, ICMP (TLS는 레코드 헤더만) |

```
캡처 ──▶ 계층별 해석 ──▶ TCP 연결 추적 · traceroute ──▶ 화면 · 로그 · pcap
Captured    PacketInfo          Connection · Hop
```

출력 예시 (목표):

```
#12  14:03:11.123456  OUT  TCP  10.0.2.15:51234 -> 34.223.124.45:80  len=132
  [IP  ] ver=4 hlen=20 total=132 id=0x1c2d flags=DF ttl=64 proto=6(TCP) cksum=0x8a1f(ok)
         src=10.0.2.15 dst=34.223.124.45
  [TCP ] sport=51234 dport=80 seq=1 ack=1 hlen=32 flags=ACK,PSH win=502
  [HTTP] GET / HTTP/1.1
         Host: neverssl.com
```

---

## 환경

| 항목 | 내용 |
|---|---|
| 운영체제 | Ubuntu 22.04 이상 (윈도우 PC는 VirtualBox **브리지 모드**) |
| 언어 | Python 3 표준 라이브러리만 (scapy, libpcap 사용 안 함) |
| 권한 | `sudo` (AF_PACKET raw socket) |
| 분석 대상 | IPv4 (트래픽 발생 시 `-4` 옵션) |

## 실행 방법

```bash
git clone https://github.com/Wireshrimp-2026/wireshrimp.git
cd wireshrimp
```

분석기 실행 (저장소 루트에서, `Ctrl+C`로 종료):

```bash
sudo python3 -m src.main --iface enp0s3 --proto http,dns --log results/http.txt --pcap results/http.pcap
```

다른 터미널에서 트래픽 발생:

```bash
curl -4 http://neverssl.com
```

| 옵션 | 필수 | 설명 |
|---|---|---|
| `--iface` | O | 캡처할 인터페이스 (`ip -br link`로 확인) |
| `--proto` | | `http,dns,smtp,pop3,imap,traceroute,bittorrent,tls,all` 중 쉼표 구분 (기본 `all`) |
| `--host` | | 이 IP와 주고받은 패킷만 (DNS는 예외) |
| `--port` | | 포트 재지정. 예: `smtp=2525,pop3=2110,imap=2143` |
| `--hex` | | 원본 바이트 hex 덤프도 출력 |
| `--log` | | 화면 출력을 파일에도 저장 |
| `--pcap` | | 캡처한 프레임을 pcap으로 저장 (Wireshark로 열어 비교) |
| `--count` | | N개 패킷을 받으면 종료 |

프로토콜별 트래픽 발생 방법:

| 프로토콜 | 명령 |
|---|---|
| HTTP + DNS | `curl -4 http://neverssl.com` |
| DNS | `dig @8.8.8.8 example.com A` · `dig +tcp @8.8.8.8 example.com` |
| SMTP · POP3 · IMAP | 다른 PC에서 `tools/mail_server.py` 실행 후 `curl smtp://…` · `curl pop3://…` · `curl imap://…` |
| traceroute | `traceroute -4 neverssl.com` · `sudo traceroute -4 -I neverssl.com` |
| BitTorrent | `transmission-cli -et -w /tmp/bt ubuntu-…-desktop-amd64.iso.torrent` (암호화 끔) |

자세한 명령은 [DESIGN.md 8장](docs/DESIGN.md#8-트래픽-발생과-시연-절차) 참고.

테스트 실행:

```bash
python3 -m unittest discover -s tests -t .
```

> 지금은 뼈대 단계입니다. 아직 구현되지 않은 모듈은 실행 시 `미구현 — 이 단계는 건너뜁니다`로 한 번 알리고 넘어가며, 출력은 임시 한 줄 형식으로 나옵니다.

## 폴더 구조

```
wireshrimp/
├─ README.md
├─ docs/DESIGN.md              설계 문서 (데이터 형식·함수 약속·출력 형식)
├─ src/
│  ├─ main.py                  실행 시작점, 옵션, 전체 연결              A
│  ├─ models.py                데이터 형식 (수정은 팀 합의)              A
│  ├─ capture.py               캡처 (AF_PACKET, OUT/IN, 필터)
│  ├─ pcap.py                  pcap 저장                               A
│  ├─ output.py                화면·로그 출력                           A
│  ├─ tcp_track.py             TCP 연결 추적                            A
│  ├─ route.py                 traceroute 홉 표                        B
│  └─ decode/
│     ├─ __init__.py           decode(): 계층 파서 합치기                A
│     ├─ link_ip.py            Ethernet, IPv4                          A
│     ├─ transport.py          TCP, UDP                                A
│     ├─ app_select.py         parse_app(): 응용 프로토콜 판별            B
│     ├─ app_http.py           HTTP                                    B
│     ├─ app_dns.py            DNS                                     B
│     ├─ app_mail.py           SMTP, POP3, IMAP                        B
│     ├─ app_bt.py             BitTorrent                              B
│     ├─ app_tls.py            TLS 레코드 헤더                          B
│     └─ icmp.py               ICMP                                    B
├─ tools/
│  └─ mail_server.py           평문 메일 테스트 서버 (트래픽 발생용)
├─ tests/                      단위 테스트, samples/ (Wireshark hex 샘플)
└─ results/                    로그, pcap, 화면 캡처
```

## 역할 분배

| 담당 | 맡는 부분 |
|---|---|
| **A** — 패킷·연결·출력 | Ethernet·IP·TCP·UDP 헤더 (IP·UDP 체크섬 검증), TCP 연결 추적, `decode()` 합치기, 실행 흐름, 화면·로그 출력, pcap 저장 |
| **B** — 응용 프로토콜·traceroute | 프로토콜 판별, HTTP, DNS, SMTP·POP3·IMAP, BitTorrent, TLS 레코드, ICMP, traceroute |

- 자기 파일만 고친다. 서로 맞추는 것은 [`src/models.py`](src/models.py)의 데이터 형식과 DESIGN.md 6장의 함수 약속뿐이다.
- 공개 함수의 이름·입력·출력은 바꾸지 않는다. 도우미 함수는 자유롭게 추가.
- 파서는 데이터가 짧거나 깨졌으면 `ValueError`. 알 수 없는 값은 0이 아니라 `None`.
- **UDP 체크섬은 반드시 검증한다** — 의사 헤더(출발지·목적지 IP, Protocol 17, UDP Length) 포함, 값이 0이면 "안 씀"(`None`). ([DESIGN.md 7.2](docs/DESIGN.md#72-tcpudp-헤더))

완료 기준은 [DESIGN.md 10.1](docs/DESIGN.md#101-완료-기준) 참고.

## 개발 규칙 (GitHub)

| 규칙 | 내용 |
|---|---|
| 저장소 | 조직 [`Wireshrimp-2026`](https://github.com/orgs/Wireshrimp-2026/repositories) 아래 `wireshrimp` |
| `main` | 항상 실행되는 상태 유지 |
| 브랜치 | A `feat/packet` `feat/output` · B `feat/app` `feat/route` |
| PR 필요 | 새 기능, 남의 파일, `models.py`, `main.py` → 다른 한 명이 확인 후 merge |
| 바로 push | 내 파일의 작은 수정, 오타 (push 전 `git pull`) |
| 커밋 메시지 | `[DNS] MX 레코드 해석 (#12)` 처럼 앞에 기능·프로토콜, 끝에 issue 번호 |

### Issue 규칙 — 역할별로 만든다

- **작업을 시작하기 전에 자기 역할의 issue를 먼저 만든다.** issue 하나 = 작업 하나.
- 제목 앞에 역할: `[A] UDP 체크섬 검증`, `[B] DNS 이름 압축 포인터 처리`
- 라벨 `role:A` / `role:B` (+ 필요하면 `bug`), Assignee는 그 역할을 맡은 사람.
- 본문: 할 일, 고칠 파일, 완료 기준.
- PR 본문에 `Closes #번호` → merge되면 issue 자동 종료.
- **다른 역할의 파일에 고칠 점이 생기면 직접 고치지 않고** 그 역할 라벨로 issue를 만들어 넘긴다.
- `models.py`·함수 약속 변경은 `role:A`·`role:B` 둘 다 붙인 issue로 먼저 합의한다.

```bash
git switch -c feat/app
```

```bash
git pull --rebase origin main && git push -u origin feat/app
```

## 일정

| 날짜 | 할 일 |
|---|---|
| ~11/23 | 필수(HTTP·DNS)까지 출력되게 |
| ~11/24 | 선택(메일·traceroute·BitTorrent) 마무리 |
| 11/25 | 전체 실행, Wireshark와 비교, 화면 캡처 |
| 11/26 | 설계보고서 PPT 8쪽 |
| ~11/27(금) 19:00 | 설계보고서 PPT + 소스 eclass 제출 |
