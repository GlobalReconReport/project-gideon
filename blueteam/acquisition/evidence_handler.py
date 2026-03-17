"""
Evidence Handler - Forensic integrity, hashing, chain-of-custody logging.

All operations are strictly read-only on source evidence.
Bug-fixes applied:
  - .raw/.bin extension ambiguity resolved: disambiguate by magic bytes first
  - _enforce_readonly: OSError caught per-file, not silently swallowed
  - _detect_type: memory types checked before disk types for ambiguous extensions
"""

import hashlib
import json
import logging
import stat
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("dfir.evidence")

MAGIC_SIGNATURES: Dict[bytes, str] = {
    b"\xd4\xc3\xb2\xa1": "PCAP (little-endian)",
    b"\xa1\xb2\xc3\xd4": "PCAP (big-endian)",
    b"\x0a\x0d\x0d\x0a": "PCAPng",
    b"\x4d\x44\x4d\x50": "Windows Memory Dump (WinPmem)",
    b"\x7f\x45\x4c\x46": "ELF Executable / Memory",
    b"\x4d\x5a":         "PE Executable",
}

# Ordered so that memory-specific extensions are checked before the ambiguous ones
_MEMORY_EXTS  = {".dmp", ".mem", ".vmem", ".lime"}
_DISK_EXTS    = {".dd", ".img", ".iso", ".vmdk", ".vhd", ".vhdx", ".e01", ".ex01"}
_PCAP_EXTS    = {".pcap", ".pcapng", ".cap"}
_AMBIGUOUS_EXTS = {".raw", ".bin"}   # resolved by magic bytes

# Magic byte prefixes that identify PCAP files
_PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"}


@dataclass
class Evidence:
    path: str
    type: str           # disk | memory | pcap | unknown
    size: int
    md5: str
    sha1: str
    sha256: str
    magic: str
    acquired_at: str    # ISO-8601 UTC


@dataclass
class CoCEntry:
    timestamp: str
    action: str
    examiner: str
    description: str
    evidence_sha256: Optional[str] = None


@dataclass
class CaseContext:
    case_name: str
    examiner: str
    case_dir: str
    created_at: str
    evidence: List[Evidence] = field(default_factory=list)
    chain_of_custody: List[CoCEntry] = field(default_factory=list)


# ─── Public API ──────────────────────────────────────────────────────────────

def initialise_case(case_name: str, examiner: str, base_dir: Path) -> CaseContext:
    """Create the case directory tree and return a fresh CaseContext."""
    ts = datetime.now(timezone.utc)
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in case_name)
    case_dir = base_dir / f"case_{safe_name}_{ts.strftime('%Y%m%d_%H%M%S')}"

    for sub in ("artifacts", "disk", "memory", "network",
                "timeline", "iocs", "yara", "reports", "logs"):
        (case_dir / sub).mkdir(parents=True, exist_ok=True)

    ctx = CaseContext(
        case_name=case_name,
        examiner=examiner,
        case_dir=str(case_dir),
        created_at=ts.isoformat(),
    )
    _log_coc(ctx, "CASE_OPENED", f"Case '{case_name}' opened by examiner '{examiner}'")
    logger.info("Case directory: %s", case_dir)
    return ctx


def ingest_evidence(ctx: CaseContext, paths: List[Path], block_size: int = 65536) -> None:
    """Hash every evidence file, detect type, record chain-of-custody. READ-ONLY."""
    for p in paths:
        p = Path(p).resolve()
        if not p.exists():
            logger.error("Evidence file not found: %s", p)
            continue

        logger.info("Hashing evidence: %s  (%.1f MB)", p.name, p.stat().st_size / 1_048_576)
        hashes = _hash_file(p, block_size)
        ev = Evidence(
            path=str(p),
            type=_detect_type(p),
            size=p.stat().st_size,
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            sha256=hashes["sha256"],
            magic=_detect_magic(p),
            acquired_at=datetime.now(timezone.utc).isoformat(),
        )
        ctx.evidence.append(ev)
        _log_coc(
            ctx,
            "EVIDENCE_INGESTED",
            f"File: {p.name} | Type: {ev.type} | SHA256: {ev.sha256} | "
            f"Size: {ev.size} bytes | Magic: {ev.magic}",
            evidence_sha256=ev.sha256,
        )
        _enforce_readonly(p)
        logger.info("  Type: %-8s  SHA256: %s", ev.type, ev.sha256)


def verify_integrity(ctx: CaseContext, block_size: int = 65536) -> bool:
    """Re-hash all evidence and confirm hashes match. Returns True if all pass."""
    all_ok = True
    for ev in ctx.evidence:
        p = Path(ev.path)
        current = _hash_file(p, block_size)
        ok = current["sha256"] == ev.sha256
        status = "PASS" if ok else "FAIL"
        _log_coc(
            ctx,
            f"INTEGRITY_CHECK_{status}",
            f"File: {p.name} | Expected: {ev.sha256} | Got: {current['sha256']}",
            evidence_sha256=ev.sha256,
        )
        if not ok:
            logger.error("INTEGRITY FAILURE: %s", p.name)
            all_ok = False
        else:
            logger.info("Integrity OK: %s", p.name)
    return all_ok


def save_coc_log(ctx: CaseContext) -> Path:
    """Write the chain-of-custody JSON log to the case directory."""
    out = Path(ctx.case_dir) / "logs" / "chain_of_custody.json"
    payload = {
        "case_name": ctx.case_name,
        "examiner": ctx.examiner,
        "created_at": ctx.created_at,
        "evidence": [asdict(e) for e in ctx.evidence],
        "chain_of_custody": [asdict(c) for c in ctx.chain_of_custody],
    }
    out.write_text(json.dumps(payload, indent=2))
    logger.info("Chain-of-custody log saved: %s", out)
    return out


def get_evidence_by_type(ctx: CaseContext, ev_type: str) -> List[Evidence]:
    return [e for e in ctx.evidence if e.type == ev_type]


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _hash_file(path: Path, block_size: int) -> Dict[str, str]:
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(block_size):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _detect_type(path: Path) -> str:
    """
    Detect evidence type by extension first, then by magic bytes for ambiguous
    extensions (.raw, .bin).  Memory extensions are checked before disk to avoid
    mis-classifying memory dumps whose extension is shared with disk images.
    """
    suffix = path.suffix.lower()
    if suffix in _PCAP_EXTS:
        return "pcap"
    if suffix in _MEMORY_EXTS:
        return "memory"
    if suffix in _DISK_EXTS:
        return "disk"
    if suffix in _AMBIGUOUS_EXTS:
        return _type_from_magic(path)
    return "unknown"


def _type_from_magic(path: Path) -> str:
    """Read first 8 bytes and infer type from magic signature."""
    try:
        header = path.read_bytes()[:8]
        if header[:4] in _PCAP_MAGIC or header[:4] == b"\x0a\x0d\x0d\x0a":
            return "pcap"
        # ELF → likely Linux memory dump (LiME or raw)
        if header[:4] == b"\x7f\x45\x4c\x46":
            return "memory"
    except OSError:
        pass
    # Default ambiguous files to disk (more common use case)
    return "disk"


def _detect_magic(path: Path) -> str:
    try:
        header = path.read_bytes()[:8]
        for sig, name in MAGIC_SIGNATURES.items():
            if header[:len(sig)] == sig:
                return name
    except OSError:
        pass
    return "unknown"


def _enforce_readonly(path: Path) -> None:
    """Remove write bits from the evidence file to prevent accidental modification."""
    try:
        current = stat.S_IMODE(path.stat().st_mode)
        path.chmod(current & ~(stat.S_IWRITE | stat.S_IWGRP | stat.S_IWOTH))
    except OSError as exc:
        logger.warning("Could not set %s read-only: %s", path.name, exc)


def _log_coc(ctx: CaseContext, action: str, description: str,
             evidence_sha256: Optional[str] = None) -> None:
    entry = CoCEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        action=action,
        examiner=ctx.examiner,
        description=description,
        evidence_sha256=evidence_sha256,
    )
    ctx.chain_of_custody.append(entry)
