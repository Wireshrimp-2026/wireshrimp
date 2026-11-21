# =============================================================================
# 담당자  : B
# 맡은 기능: DNS 해석 (DESIGN 7.4) — 필수
#            - 헤더: ID, Flags(QR, Opcode, AA, TC, RD, RA, Z, RCODE), QD/AN/NS/AR COUNT
#            - Question: 이름, Type, Class
#            - Answer/Authority/Additional: 이름, Type, Class, TTL, RDLENGTH,
#              RDATA (A, AAAA, CNAME, NS, MX, PTR, TXT, SOA, 그 밖은 hex)
#            - 이름 압축 포인터(0xC0) 처리, 포인터 무한 반복 방지
#            - over_tcp면 앞 2바이트 길이를 이 함수가 뗀다 (dig +tcp)
# 완료 기준: DNS 헤더·플래그·질의·응답(A, AAAA, CNAME, MX)이 UDP·TCP 모두 AppInfo로 나온다.
# =============================================================================
from __future__ import annotations

from ..models import AppInfo


def parse_dns(data: bytes, over_tcp: bool = False) -> AppInfo:
    """DNS 메시지 → AppInfo(name="DNS").

    summary 예: "Standard query 0x1a2b A neverssl.com"
               "Standard query response 0x1a2b A 34.223.124.45"
    fields 키: txid, is_response, opcode, rcode, flags(dict), questions(list), answers(list),
              authority(list), additional(list)
    """
    raise NotImplementedError
