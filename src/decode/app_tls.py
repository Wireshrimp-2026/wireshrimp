# =============================================================================
# 담당자  : B
# 맡은 기능: TLS 레코드 헤더 표시 (DESIGN 7.9) — 내용은 암호화되어 해석하지 않음
#            - 레코드 헤더 5바이트만 해석: Content Type(20 ChangeCipherSpec, 21 Alert, 22 Handshake,
#              23 Application Data, 24 Heartbeat), Version(0x0300 SSL 3.0, 0x0301~0x0304 TLS 1.0~1.3),
#              Length
#            - 한 세그먼트에 레코드가 여러 개면 Length만큼 건너뛰며 레코드마다 한 줄
#              (첫 레코드가 summary, 둘째부터 lines. MAX_RECORD_LINES개가 넘으면 나머지는 개수만)
#            - 마지막 레코드(또는 다음 레코드 헤더)가 다음 세그먼트로 이어지면 그렇다고 표시
#            - 레코드 헤더로 시작하지 않는 세그먼트(앞 레코드가 이어지는 중)는 None → [DATA]
#              헤더 모양 = Content Type·Version이 위 값이고 Length가 MAX_RECORD_LEN 이하
#            - 첫 레코드는 헤더 모양인데 그 뒤가 아니면 깨진 데이터 → ValueError
#            - 레코드의 Version은 실제로 고른 버전과 다를 수 있다 (Wireshark도 같게 보임):
#              ClientHello는 보통 TLS 1.0, TLS 1.3 연결도 TLS 1.2 (RFC 8446 5.1).
#              고른 버전은 Handshake 내용(supported_versions)에 있어 여기서는 모른다
# 완료 기준: 443·465·993·995 포트의 세그먼트가 "TLS record type=…" AppInfo로 나온다.
# =============================================================================
from __future__ import annotations

import struct
from typing import Optional

from ..models import AppInfo

HEADER_LEN = 5                     # Content Type 1 + Version 2 + Length 2
MAX_RECORD_LEN = 2 ** 14 + 2048    # 암호화된 레코드의 최대 Length (RFC 5246 6.2.3)
MAX_RECORD_LINES = 10              # 화면에 찍을 레코드 수 (summary 포함). 나머지는 개수만

CONTENT_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "Application Data",
                 24: "Heartbeat"}
VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2",
            0x0304: "TLS 1.3"}


def parse_tls(data: bytes) -> Optional[AppInfo]:
    """TCP 페이로드 → AppInfo(name="TLS"), 레코드 헤더로 시작하지 않으면 None.

    summary 예: "TLS record type=22(Handshake) version=TLS 1.2 len=517" (첫 레코드)
    lines: 둘째 레코드부터 같은 모양으로 한 줄씩, 다음 세그먼트로 이어지면 끝에 안내 한 줄
    fields 키: records(list), continues(마지막 레코드나 다음 레코드 헤더가 다음 세그먼트로 이어지면 True)
              레코드 dict: content_type, type_name, version, version_name, length,
                          in_segment(이 세그먼트에 들어 있는 내용 바이트 수)
    헤더 모양으로 시작하는데 5바이트가 안 되거나, 첫 레코드 뒤가 헤더 모양이 아니면 ValueError.
    """
    if not _looks_like_header(data[:HEADER_LEN]):
        return None                  # 앞 레코드가 이어지는 중(암호문)이거나 TLS가 아님
    if len(data) < HEADER_LEN:
        raise ValueError(f"TLS record header truncated: {len(data)} of {HEADER_LEN} bytes")

    records: list[dict] = []
    off = 0
    while off + HEADER_LEN <= len(data):
        if not _looks_like_header(data[off:off + HEADER_LEN]):
            raise ValueError(f"TLS record #{len(records) + 1} at offset {off}: not a record header")
        ctype, version, length = struct.unpack_from("!BHH", data, off)
        records.append({"content_type": ctype, "type_name": CONTENT_TYPES[ctype],
                        "version": version, "version_name": VERSIONS[version], "length": length,
                        "in_segment": min(length, len(data) - off - HEADER_LEN)})
        off += HEADER_LEN + length
    cut_header = data[off:]          # 1~4바이트 = 다음 레코드 헤더의 앞부분만 이 세그먼트에 있음
    if cut_header and not _looks_like_header(cut_header):
        raise ValueError(f"TLS record #{len(records) + 1} at offset {off}: not a record header")

    lines = [_record_line(r) for r in records[1:MAX_RECORD_LINES]]
    if len(records) > MAX_RECORD_LINES:
        lines.append(f"… 레코드 {len(records) - MAX_RECORD_LINES}개 더 (모두 {len(records)}개)")
    last = records[-1]
    body_continues = last["in_segment"] < last["length"]
    if body_continues:
        lines.append(f"(레코드가 다음 세그먼트로 이어짐: 이 세그먼트에 "
                     f"{last['in_segment']}/{last['length']} bytes)")
    elif cut_header:
        lines.append(f"(다음 레코드 헤더가 다음 세그먼트로 이어짐: 이 세그먼트에 "
                     f"{len(cut_header)}/{HEADER_LEN} bytes)")
    return AppInfo(name="TLS", summary=_record_line(records[0]), lines=lines,
                   fields={"records": records, "continues": body_continues or bool(cut_header)})


def _looks_like_header(head: bytes) -> bool:
    """head(레코드 헤더 5바이트, 또는 잘린 앞부분 1~4바이트)가 레코드 헤더 모양인지.

    Content Type·Version이 아는 값이고 Length가 MAX_RECORD_LEN 이하. 잘렸으면 있는 바이트만 본다.
    암호문(아무렇게나 생긴 바이트)이 우연히 통과할 확률은 100만분의 1보다 작다.
    """
    n = len(head)
    if n == 0 or head[0] not in CONTENT_TYPES:
        return False
    if n == 2 and head[1] != 0x03:                        # Version 앞 바이트는 늘 3
        return False
    if n >= 3 and ((head[1] << 8) | head[2]) not in VERSIONS:
        return False
    if n >= 4 and ((head[3] << 8) | (head[4] if n >= 5 else 0)) > MAX_RECORD_LEN:
        return False
    return True


def _record_line(r: dict) -> str:
    return (f"TLS record type={r['content_type']}({r['type_name']}) "
            f"version={r['version_name']} len={r['length']}")
