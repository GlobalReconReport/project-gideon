"""
Memory Analyzer - Volatility 3 orchestration.

Bug-fixes applied:
  - _flag_suspicious: process name uses `or` operator, not chained get()
  - _flag_suspicious: malfind severity distinguishes EXECUTE+WRITE (critical)
    from EXECUTE-only (high) from WRITE-only (medium)
  - _detect_os: unknown profile logs warning before defaulting to windows
  - _parse_table: returns [] rather than crashing on single-line output
  - _exec_vol: non-zero returncode is logged but output is still returned
    (Volatility sometimes exits non-zero with valid partial output)
"""

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("dfir.memory")


@dataclass
class MemoryFinding:
    source: str = "memory"
    os_profile: str = "unknown"
    processes: List[Dict] = field(default_factory=list)
    cmdlines: List[Dict] = field(default_factory=list)
    network_connections: List[Dict] = field(default_factory=list)
    malfind_regions: List[Dict] = field(default_factory=list)
    loaded_dlls: List[Dict] = field(default_factory=list)
    file_handles: List[Dict] = field(default_factory=list)
    registry_hives: List[Dict] = field(default_factory=list)
    hashes: List[Dict] = field(default_factory=list)
    raw_outputs: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    suspicious_processes: List[Dict] = field(default_factory=list)


WINDOWS_PLUGINS = [
    ("windows.pslist",            "processes"),
    ("windows.pstree",            None),
    ("windows.cmdline",           "cmdlines"),
    ("windows.netscan",           "network_connections"),
    ("windows.netstat",           None),
    ("windows.malfind",           "malfind_regions"),
    ("windows.dlllist",           "loaded_dlls"),
    ("windows.filescan",          "file_handles"),
    ("windows.registry.hivelist", "registry_hives"),
    ("windows.hashdump",          "hashes"),
    ("windows.lsadump",           None),
]

LINUX_PLUGINS = [
    ("linux.pslist",   "processes"),
    ("linux.pstree",   None),
    ("linux.bash",     "cmdlines"),
    ("linux.netstat",  "network_connections"),
    ("linux.malfind",  "malfind_regions"),
    ("linux.lsof",     "file_handles"),
    ("linux.mountinfo", None),
]

_SUSPICIOUS_NAMES = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "nc.exe", "ncat.exe", "nmap.exe",
    "mimikatz.exe", "psexec.exe", "psexecsvc.exe",
}


def analyse(memory_path: str, case_dir: str, tools: Dict[str, str],
            plugin_list: Optional[List[str]] = None,
            tool_timeout: int = 3600) -> MemoryFinding:
    result = MemoryFinding()
    mem_dir = Path(case_dir) / "memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    vol = tools.get("volatility", "vol")
    mem = Path(memory_path)

    logger.info("[MEM] Analysing: %s", mem.name)

    result.os_profile = _detect_os(vol, mem, tool_timeout)
    logger.info("[MEM] Detected OS profile: %s", result.os_profile)

    if plugin_list:
        plugins_to_run = [(p, None) for p in plugin_list]
    elif result.os_profile == "linux":
        plugins_to_run = LINUX_PLUGINS
    else:
        plugins_to_run = WINDOWS_PLUGINS

    for plugin, attr in plugins_to_run:
        raw = _run_plugin(vol, mem, plugin, mem_dir, tool_timeout)
        if raw is None:
            result.errors.append(f"{plugin} failed")
            continue
        result.raw_outputs[plugin] = raw
        if attr:
            parsed = _parse_plugin_output(plugin, raw)
            if parsed is not None:
                setattr(result, attr, parsed)

    result.suspicious_processes = _flag_suspicious(result)

    logger.info(
        "[MEM] Done. Processes=%d  NetConns=%d  Malfind=%d  Suspicious=%d",
        len(result.processes),
        len(result.network_connections),
        len(result.malfind_regions),
        len(result.suspicious_processes),
    )
    return result


# ─── OS detection ─────────────────────────────────────────────────────────────

def _detect_os(vol: str, mem: Path, timeout: int) -> str:
    try:
        out = _exec_vol(vol, mem, "windows.info", timeout)
        if out and "Kernel Base" in out:
            return "windows"
    except _VolError:
        pass
    try:
        out = _exec_vol(vol, mem, "linux.pslist", timeout)
        if out:
            return "linux"
    except _VolError:
        pass
    logger.warning("[MEM] Could not auto-detect OS profile; defaulting to windows")
    return "windows"


# ─── Plugin execution ─────────────────────────────────────────────────────────

def _run_plugin(vol: str, mem: Path, plugin: str, out_dir: Path,
                timeout: int) -> Optional[str]:
    logger.info("[MEM] Plugin: %s", plugin)
    try:
        raw = _exec_vol(vol, mem, plugin, timeout)
        (out_dir / f"{plugin.replace('.', '_')}.txt").write_text(raw or "")
        return raw
    except _VolError as exc:
        logger.warning("[MEM] %s skipped: %s", plugin, exc)
        return None


def _exec_vol(vol: str, mem: Path, plugin: str, timeout: int) -> str:
    cmd = [vol, "-f", str(mem), plugin]
    logger.debug("[MEM] Exec: %s", " ".join(cmd))
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if res.returncode != 0:
            logger.debug("[MEM] %s exited %d (may have partial output)", plugin, res.returncode)
        return res.stdout
    except FileNotFoundError:
        raise _VolError(f"Volatility not found: {vol}")
    except subprocess.TimeoutExpired:
        raise _VolError(f"Volatility timed out running {plugin}")


class _VolError(RuntimeError):
    pass


# ─── Output parsers ───────────────────────────────────────────────────────────

def _parse_plugin_output(plugin: str, raw: str) -> Optional[List[Dict]]:
    parsers = {
        "windows.pslist":            _parse_table,
        "linux.pslist":              _parse_table,
        "windows.cmdline":           _parse_cmdline,
        "linux.bash":                _parse_table,
        "windows.netscan":           _parse_netscan,
        "windows.netstat":           _parse_netscan,
        "linux.netstat":             _parse_netscan,
        "windows.malfind":           _parse_malfind,
        "linux.malfind":             _parse_malfind,
        "windows.dlllist":           _parse_table,
        "windows.filescan":          _parse_table,
        "linux.lsof":                _parse_table,
        "windows.registry.hivelist": _parse_table,
        "windows.hashdump":          _parse_table,
    }
    parser = parsers.get(plugin, _parse_table)
    try:
        return parser(raw)
    except Exception as exc:
        logger.warning("[MEM] Parse error for %s: %s", plugin, exc)
        return []


def _parse_table(raw: str) -> List[Dict]:
    lines = [l for l in raw.splitlines() if l.strip() and not l.startswith("*")]
    if len(lines) < 2:
        return []
    header = re.split(r"\t|\s{2,}", lines[0].strip())
    rows = []
    for line in lines[1:]:
        cells = re.split(r"\t|\s{2,}", line.strip())
        if cells:
            rows.append(dict(zip(header, cells + [""] * max(0, len(header) - len(cells)))))
    return rows


def _parse_cmdline(raw: str) -> List[Dict]:
    results = []
    pid_re = re.compile(r"^(\d+)\s+(\S+)\s+(.*)")
    for line in raw.splitlines():
        m = pid_re.match(line.strip())
        if m:
            results.append({"PID": m.group(1), "Process": m.group(2), "Args": m.group(3)})
    return results


def _parse_netscan(raw: str) -> List[Dict]:
    lines = raw.splitlines()
    if not lines:
        return []
    header_idx = next(
        (i for i, l in enumerate(lines) if "LocalAddr" in l or "Local Address" in l), None
    )
    if header_idx is None:
        return _parse_table(raw)
    header = re.split(r"\t|\s{2,}", lines[header_idx].strip())
    rows = []
    for line in lines[header_idx + 1:]:
        if not line.strip():
            continue
        cells = re.split(r"\t|\s{2,}", line.strip())
        rows.append(dict(zip(header, cells + [""] * max(0, len(header) - len(cells)))))
    return rows


def _parse_malfind(raw: str) -> List[Dict]:
    entries = []
    current: Dict[str, Any] = {}
    hex_lines: List[str] = []

    for line in raw.splitlines():
        if not line.strip():
            if current:
                current["hexdump"] = "\n".join(hex_lines)
                entries.append(current)
                current = {}
                hex_lines = []
            continue

        pid_m = re.match(r"^(\d+)\s+(\S+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)", line)
        if pid_m:
            if current:
                current["hexdump"] = "\n".join(hex_lines)
                entries.append(current)
                hex_lines = []
            current = {
                "PID":       pid_m.group(1),
                "Process":   pid_m.group(2),
                "StartVPN":  pid_m.group(3),
                "EndVPN":    pid_m.group(4),
                "Protection": "",
            }
            prot_m = re.search(r"(PAGE_[A-Z_]+)", line[pid_m.end():])
            if prot_m:
                current["Protection"] = prot_m.group(1)
            continue

        if re.match(r"^[0-9a-fA-F]{8,}", line.strip()):
            hex_lines.append(line.strip())
        elif "Protection" in line and current:
            prot_m = re.search(r"(PAGE_[A-Z_]+)", line)
            if prot_m:
                current["Protection"] = prot_m.group(1)

    if current:
        current["hexdump"] = "\n".join(hex_lines)
        entries.append(current)
    return entries


# ─── Suspicious process analysis ─────────────────────────────────────────────

def _flag_suspicious(result: MemoryFinding) -> List[Dict]:
    suspects = []

    # Check process names (FIX: use `or` so None ImageFileName falls through to COMM)
    for proc in result.processes:
        name = (proc.get("ImageFileName") or proc.get("COMM") or "").lower().strip()
        if name in _SUSPICIOUS_NAMES:
            suspects.append({
                "reason":   f"Suspicious process name: {name}",
                "severity": "medium",
                **proc,
            })

    # Network-connected processes with anomalous PPID
    net_pids = {str(c.get("PID", "")) for c in result.network_connections}
    for proc in result.processes:
        pid  = str(proc.get("PID", ""))
        ppid = str(proc.get("PPID", ""))
        name = (proc.get("ImageFileName") or proc.get("COMM") or "").lower()
        if pid in net_pids and ppid in ("0", "4") and name not in ("system", "idle"):
            suspects.append({
                "reason":   f"Network-connected process with anomalous PPID={ppid}",
                "severity": "high",
                **proc,
            })

    # Malfind: severity based on protection flags (FIX: was OR, now AND for critical)
    for region in result.malfind_regions:
        prot = str(region.get("Protection", ""))
        if "EXECUTE" in prot and "WRITE" in prot:
            sev = "critical"   # RWX / EXECUTE_READWRITE — classic injection
        elif "EXECUTE" in prot:
            sev = "high"       # executable but not writable — unusual but less certain
        elif "WRITE" in prot:
            sev = "medium"     # writable but not executable
        else:
            continue           # skip if neither — not clearly suspicious
        suspects.append({
            "reason":   f"Suspicious memory region: {prot}",
            "severity": sev,
            **region,
        })

    return suspects
