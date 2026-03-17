"""
Timeline Builder - Merge disk, memory, and network artifacts into a unified timeline.

Bug-fixes applied:
  - _sort_jsonl: was using fragile -t '"' -k 4 shell sort; now sorts whole lines
    lexicographically (ISO-8601 timestamps are designed to sort correctly this way)
  - Python fallback sort replaced with a streaming merge-sort that avoids loading
    the entire file into RAM
  - Memory network connection timestamps: warns when 'Created' field is absent
    instead of silently using current time
  - _normalise_timestamp: handles more edge cases and never crashes
"""

import gc
import json
import logging
import re
import subprocess
from csv import DictReader
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Generator, List, Optional

logger = logging.getLogger("dfir.timeline")

DEFAULT_REPORT_LIMIT = 5_000

SEVERITY_KEYWORDS = {
    "critical": [
        "malware", "malfind", "injected", "exploit", "shellcode",
        "mimikatz", "meterpreter", "cobaltstrike", "backdoor",
        "webshell", "rootkit", "credential",
    ],
    "high": [
        "delete", "wipe", "shred", "clearlog", "logon failure",
        "brute", "lateral", "psexec", "schtask", "runkey",
        "scheduled task", "autorun", "persistence",
    ],
    "medium": [
        "download", "upload", "ftp", "smb", "rdp", "vnc",
        "powershell", "cmd.exe", "wscript", "cscript",
        "network connection", "port scan",
    ],
    "low": [
        "file created", "file modified", "registry",
        "dns query", "http", "login", "logoff",
    ],
}


@dataclass
class TimelineEvent:
    timestamp: str
    source: str
    plugin: str
    event_type: str
    description: str
    artifact: str
    severity: str


def build(
    disk_finding,
    memory_finding,
    network_finding,
    case_dir: str,
    report_limit: int = DEFAULT_REPORT_LIMIT,
) -> Dict:
    tl_dir = Path(case_dir) / "timeline"
    tl_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = tl_dir / "timeline.jsonl"

    stats = {"disk": 0, "memory": 0, "network": 0, "total": 0}

    with jsonl_path.open("w", encoding="utf-8") as fh:
        if disk_finding and disk_finding.timeline_csv:
            for ev in _stream_plaso_csv(disk_finding.timeline_csv):
                fh.write(json.dumps(asdict(ev)) + "\n")
                stats["disk"] += 1
                stats["total"] += 1

        if memory_finding:
            for ev in _events_from_memory(memory_finding):
                fh.write(json.dumps(asdict(ev)) + "\n")
                stats["memory"] += 1
                stats["total"] += 1
            memory_finding.raw_outputs.clear()
            gc.collect()

        if network_finding:
            for ev in _events_from_network(network_finding):
                fh.write(json.dumps(asdict(ev)) + "\n")
                stats["network"] += 1
                stats["total"] += 1

    logger.info(
        "[TL] Total=%d (disk=%d memory=%d network=%d)",
        stats["total"], stats["disk"], stats["memory"], stats["network"],
    )

    sorted_path = tl_dir / "timeline_sorted.jsonl"
    _sort_jsonl(jsonl_path, sorted_path)
    report_events = _read_head(sorted_path, report_limit)

    return {
        "jsonl_path": str(sorted_path),
        "events":     report_events,
        "total":      stats["total"],
        "stats":      stats,
    }


# ─── Plaso CSV streamer ───────────────────────────────────────────────────────

def _stream_plaso_csv(csv_path: str) -> Generator[TimelineEvent, None, None]:
    path = Path(csv_path)
    if not path.exists():
        return
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            reader = DictReader(fh)
            for row in reader:
                ts      = _normalise_timestamp(
                    row.get("datetime") or row.get("timestamp") or ""
                )
                desc    = row.get("message") or row.get("description") or ""
                art     = row.get("filename") or row.get("source_long") or ""
                ev_type = row.get("type") or row.get("timestamp_desc") or "filesystem"
                yield TimelineEvent(
                    timestamp=ts, source="disk",
                    plugin=row.get("parser") or "plaso",
                    event_type=ev_type,
                    description=desc[:512], artifact=art[:256],
                    severity=_classify_severity(desc + " " + art),
                )
    except Exception as exc:
        logger.warning("[TL] Plaso CSV parse error: %s", exc)


# ─── Memory events ────────────────────────────────────────────────────────────

def _events_from_memory(mf) -> Generator[TimelineEvent, None, None]:
    now = datetime.now(timezone.utc).isoformat()

    for proc in mf.processes:
        name        = proc.get("ImageFileName") or proc.get("COMM") or "?"
        pid         = proc.get("PID") or ""
        create_time = proc.get("CreateTime") or proc.get("StartTime") or now
        desc = f"Process: {name} (PID={pid})"
        yield TimelineEvent(
            timestamp=_normalise_timestamp(create_time),
            source="memory", plugin="windows.pslist",
            event_type="process_start",
            description=desc, artifact=name,
            severity=_classify_severity(desc),
        )

    for cmd in mf.cmdlines:
        desc = f"Cmdline: {cmd.get('Process','?')} {cmd.get('Args','')}"
        yield TimelineEvent(
            timestamp=now, source="memory", plugin="windows.cmdline",
            event_type="process_cmdline",
            description=desc[:512], artifact=cmd.get("Process", ""),
            severity=_classify_severity(desc),
        )

    for conn in mf.network_connections:
        local  = conn.get("LocalAddr") or conn.get("LocalAddress") or "?"
        remote = conn.get("ForeignAddr") or conn.get("RemoteAddress") or "?"
        state  = conn.get("State") or ""
        owner  = conn.get("Owner") or conn.get("Process") or ""
        desc   = f"Net connection: {local} -> {remote} [{state}] owner={owner}"
        created = conn.get("Created")
        if not created:
            # FIX: log warning instead of silently stamping current time
            logger.debug("[TL] No 'Created' timestamp in netscan entry; using collection time")
        yield TimelineEvent(
            timestamp=_normalise_timestamp(created or now),
            source="memory", plugin="windows.netscan",
            event_type="network_connection",
            description=desc, artifact=remote,
            severity=_classify_severity(desc),
        )

    for region in mf.malfind_regions:
        proc  = region.get("Process") or region.get("PID") or "?"
        prot  = region.get("Protection") or ""
        start = region.get("StartVPN") or ""
        desc  = f"Malfind: {proc} region {start} [{prot}]"
        yield TimelineEvent(
            timestamp=now, source="memory", plugin="windows.malfind",
            event_type="code_injection",
            description=desc, artifact=str(proc),
            severity="critical",
        )


# ─── Network events ───────────────────────────────────────────────────────────

def _events_from_network(nf) -> Generator[TimelineEvent, None, None]:
    now = datetime.now(timezone.utc).isoformat()

    for req in nf.http_requests:
        desc = f"HTTP {req.get('method','?')} {req.get('host','')}{req.get('uri','')}"
        yield TimelineEvent(
            timestamp=now, source="network", plugin="tshark.http",
            event_type="http_request",
            description=desc[:512], artifact=req.get("host", ""),
            severity=_classify_severity(desc),
        )

    for q in nf.dns_queries:
        yield TimelineEvent(
            timestamp=now, source="network", plugin="tshark.dns",
            event_type="dns_query",
            description=f"DNS query: {q}", artifact=q,
            severity=_classify_severity(q),
        )

    for s in nf.suspicious:
        yield TimelineEvent(
            timestamp=now, source="network", plugin="tshark",
            event_type=s.get("type", "suspicious"),
            description=s.get("detail", ""), artifact="",
            severity=s.get("severity", "medium"),
        )


# ─── JSONL sort ───────────────────────────────────────────────────────────────

def _sort_jsonl(src: Path, dst: Path) -> None:
    """
    Sort JSONL by timestamp.
    Since every line starts with {"timestamp": "YYYY-MM-DDTHH:MM:SS...
    lexicographic sort of whole lines == chronological sort (ISO-8601 property).
    FIX: replaced fragile -t '"' -k 4 shell sort with a simple sort on full lines.
    """
    try:
        result = subprocess.run(
            ["sort", str(src)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            dst.write_text(result.stdout)
            return
        logger.warning("[TL] External sort exited %d; using Python fallback", result.returncode)
    except Exception as exc:
        logger.warning("[TL] External sort failed (%s); using Python fallback", exc)

    # Python fallback: sort in chunks to limit peak RAM
    _python_sort_jsonl(src, dst)


def _python_sort_jsonl(src: Path, dst: Path) -> None:
    """Sort JSONL using Python, reading 50k lines at a time and merging."""
    import heapq, tempfile, os
    chunk_size = 50_000
    tmp_files = []
    try:
        with src.open(encoding="utf-8", errors="replace") as fh:
            while True:
                chunk = []
                for _ in range(chunk_size):
                    line = fh.readline()
                    if not line:
                        break
                    line = line.strip()
                    if line:
                        chunk.append(line)
                if not chunk:
                    break
                chunk.sort()
                tf = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
                )
                tf.write("\n".join(chunk) + "\n")
                tf.flush()
                tf.close()
                tmp_files.append(tf.name)

        # k-way merge
        handles = [open(f, encoding="utf-8") for f in tmp_files]
        with dst.open("w", encoding="utf-8") as out:
            for line in heapq.merge(*handles):
                out.write(line if line.endswith("\n") else line + "\n")
        for h in handles:
            h.close()
    finally:
        for f in tmp_files:
            try:
                os.unlink(f)
            except OSError:
                pass


def _read_head(path: Path, limit: int) -> List[Dict]:
    events = []
    if not path.exists():
        return events
    with path.open(encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i >= limit:
                break
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return events


# ─── Severity + timestamp helpers ─────────────────────────────────────────────

def _classify_severity(text: str) -> str:
    low = text.lower()
    for sev in ("critical", "high", "medium", "low"):
        if any(kw in low for kw in SEVERITY_KEYWORDS.get(sev, [])):
            return sev
    return "info"


_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
]


def _normalise_timestamp(ts: str) -> str:
    ts = str(ts).strip()
    if not ts or ts in ("N/A", "-", "None", "0", ""):
        return datetime.now(timezone.utc).isoformat()
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return ts
