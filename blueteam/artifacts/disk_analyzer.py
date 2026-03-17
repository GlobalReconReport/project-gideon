"""
Disk Analyzer - SleuthKit (Autopsy backend), bulk_extractor, Plaso.

Bug-fixes applied:
  - fls truncation now emits a warning with the capped count
  - _run exit-code leniency is per-invocation (bulk_extractor allows rc=1)
  - Uses shared.utils.run_tool / ToolError instead of inline duplicate
"""

import csv
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from shared.utils import ToolError, run_tool

logger = logging.getLogger("dfir.disk")

_FLS_LIMIT = 50_000


@dataclass
class DiskFinding:
    source: str = "disk"
    partitions: List[Dict] = field(default_factory=list)
    files: List[Dict] = field(default_factory=list)
    bulk_features: Dict[str, List[str]] = field(default_factory=dict)
    timeline_csv: Optional[str] = None
    plaso_storage: Optional[str] = None
    recovered_dir: Optional[str] = None
    errors: List[str] = field(default_factory=list)


def analyse(image_path: str, case_dir: str, tools: Dict[str, str],
            tool_timeout: int = 3600) -> DiskFinding:
    result = DiskFinding()
    disk_dir = Path(case_dir) / "disk"
    img = Path(image_path)
    logger.info("[DISK] Analysing: %s", img.name)

    result.partitions = _run_mmls(img, tools, tool_timeout)
    result.files      = _run_fls(img, tools, disk_dir, tool_timeout)

    be_out = disk_dir / "bulk_extractor"
    result.bulk_features = _run_bulk_extractor(img, be_out, tools, tool_timeout)

    result.timeline_csv, result.plaso_storage = _run_plaso(
        img, disk_dir, tools, tool_timeout
    )
    return result


# ─── mmls ─────────────────────────────────────────────────────────────────────

def _run_mmls(img: Path, tools: Dict, timeout: int) -> List[Dict]:
    try:
        out = run_tool(tools.get("mmls", "mmls"), [str(img)], timeout=timeout)
        partitions = []
        for line in out.splitlines():
            if not line.strip() or line.startswith(("Units", "Slot", "0:")):
                continue
            parts = line.split()
            if len(parts) >= 6:
                partitions.append({
                    "slot":   parts[0],
                    "start":  parts[1],
                    "end":    parts[2],
                    "length": parts[3],
                    "desc":   " ".join(parts[5:]),
                })
        logger.info("[DISK] mmls: %d partition(s)", len(partitions))
        return partitions
    except ToolError as exc:
        logger.warning("[DISK] mmls failed: %s", exc)
        return []


# ─── fls ─────────────────────────────────────────────────────────────────────

def _run_fls(img: Path, tools: Dict, out_dir: Path, timeout: int) -> List[Dict]:
    fls_bin = tools.get("fls", "fls")
    fls_txt = out_dir / "fls_output.txt"
    files: List[Dict] = []
    try:
        raw = run_tool(fls_bin, ["-r", "-l", str(img)], timeout=timeout)
        fls_txt.write_text(raw)
        lines = raw.splitlines()
        for line in lines:
            if not line.strip():
                continue
            entry: Dict[str, Any] = {"raw": line[:256]}
            parts = line.split("\t") if "\t" in line else line.split(None, 7)
            if len(parts) >= 2:
                entry["name"]  = parts[0].strip()
                entry["inode"] = parts[1].strip()
            files.append(entry)
        total = len(files)
        if total > _FLS_LIMIT:
            logger.warning(
                "[DISK] fls returned %d entries; capping at %d for RAM safety",
                total, _FLS_LIMIT,
            )
        logger.info("[DISK] fls: %d filesystem entries", min(total, _FLS_LIMIT))
    except ToolError as exc:
        logger.warning("[DISK] fls failed: %s", exc)
    return files[:_FLS_LIMIT]


# ─── bulk_extractor ──────────────────────────────────────────────────────────

_BULK_FEATURE_FILES = [
    "domain", "ip", "url", "email", "telephone",
    "creditcard", "pii", "elf", "winpe", "zip",
    "json", "base64", "hashes",
]


def _run_bulk_extractor(img: Path, out_dir: Path, tools: Dict, timeout: int
                        ) -> Dict[str, List[str]]:
    be = tools.get("bulk_extractor", "bulk_extractor")
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        logger.info("[DISK] Running bulk_extractor → %s", out_dir)
        # bulk_extractor exits 1 on warnings; treat 0 and 1 as success
        run_tool(be, ["-o", str(out_dir), "-R", str(img)],
                 timeout=timeout, ok_returncodes=(0, 1))
        features = _parse_bulk_output(out_dir)
        total = sum(len(v) for v in features.values())
        logger.info("[DISK] bulk_extractor: %d features across %d types",
                    total, len(features))
        return features
    except ToolError as exc:
        logger.warning("[DISK] bulk_extractor failed: %s", exc)
        return {}


def _parse_bulk_output(out_dir: Path) -> Dict[str, List[str]]:
    features: Dict[str, List[str]] = {}
    for name in _BULK_FEATURE_FILES:
        txt = out_dir / f"{name}.txt"
        if not txt.exists():
            continue
        entries = []
        for line in txt.read_text(errors="replace").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("\t")
            entries.append((parts[1] if len(parts) > 1 else parts[0]).strip())
        if entries:
            features[name] = list(dict.fromkeys(entries))
    return features


# ─── Plaso / log2timeline ────────────────────────────────────────────────────

def _run_plaso(img: Path, out_dir: Path, tools: Dict, timeout: int):
    l2t          = tools.get("log2timeline", "log2timeline.py")
    psort_bin    = tools.get("psort", "psort.py")
    plaso_storage = out_dir / "timeline.plaso"
    timeline_csv  = out_dir / "timeline.csv"

    try:
        logger.info("[DISK] Running log2timeline → %s", plaso_storage)
        run_tool(
            l2t,
            ["--storage-file", str(plaso_storage), "--parsers", "auto",
             "--no-dependencies-check", str(img)],
            timeout=timeout,
        )
    except ToolError as exc:
        logger.warning("[DISK] log2timeline failed: %s", exc)
        return None, None

    try:
        logger.info("[DISK] Running psort → %s", timeline_csv)
        run_tool(
            psort_bin,
            ["-o", "dynamic", "-w", str(timeline_csv), str(plaso_storage)],
            timeout=timeout,
        )
        logger.info("[DISK] Plaso timeline: %s", timeline_csv)
        return str(timeline_csv), str(plaso_storage)
    except ToolError as exc:
        logger.warning("[DISK] psort failed: %s", exc)
        return None, str(plaso_storage)


# ─── Timeline parse helper ────────────────────────────────────────────────────

def parse_timeline_csv(csv_path: str, limit: int = 50_000) -> List[Dict]:
    """Stream-parse a Plaso psort CSV; cap at `limit` rows."""
    events = []
    path = Path(csv_path)
    if not path.exists():
        return events
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader):
                if i >= limit:
                    break
                events.append(dict(row))
    except Exception as exc:
        logger.warning("[DISK] timeline CSV parse error: %s", exc)
    return events
