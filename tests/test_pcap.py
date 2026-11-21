# =============================================================================
# pcap 저장 단위 테스트 — 쓴 파일을 직접 읽어 형식을 확인
# =============================================================================
import os
import struct
import tempfile
import unittest

from src.models import Captured
from src.pcap import PcapWriter


class TestPcapWriter(unittest.TestCase):
    def test_header_and_records(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.pcap")
            w = PcapWriter(path)
            w.write(Captured(no=1, ts=1700000000.123456, direction="OUT", frame=b"\x01" * 60))
            w.write(Captured(no=2, ts=1700000001.9999996, direction="IN", frame=b"\x02" * 70))
            w.close()
            w.close()                                   # 두 번 닫아도 괜찮아야 함
            with open(path, "rb") as f:
                data = f.read()

        magic, major, minor, _zone, _sig, snaplen, link = struct.unpack("=IHHiIII", data[:24])
        self.assertEqual((magic, major, minor, snaplen, link), (0xA1B2C3D4, 2, 4, 262144, 1))

        sec, usec, incl, orig = struct.unpack("=IIII", data[24:40])
        self.assertEqual((sec, usec, incl, orig), (1700000000, 123456, 60, 60))
        self.assertEqual(data[40:100], b"\x01" * 60)

        sec, usec, incl, orig = struct.unpack("=IIII", data[100:116])
        self.assertEqual((sec, usec), (1700000002, 0))  # 반올림으로 1초가 되면 넘김
        self.assertEqual((incl, orig), (70, 70))
        self.assertEqual(len(data), 116 + 70)

    def test_missing_folder_raises_oserror(self):
        with self.assertRaises(OSError):
            PcapWriter("/nonexistent-folder-xyz/x.pcap")


if __name__ == "__main__":
    unittest.main()
