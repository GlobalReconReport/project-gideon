"""
Correlator - Cross-source correlation between disk, memory, and network evidence.

Bug-fixes applied:
  - Process whitelist comparison is now case-insensitive
  - IP validation rejects octets > 255
  - Empty-string guard before calling _is_private
  - network_connections type guard (or [] fallback)
"""

import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Set

logger = logging.getLogger("dfir.correlator")

_PRIVATE_IP_RE = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)"
)
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


@dataclass
class Correlation:
    title: str
    description: str
    severity: str
    sources: List[str]
    evidence: List[str]
    category: str


def correlate(disk_finding, memory_finding, network_finding) -> List[Dict]:
    correlations: List[Correlation] = []

    mem_ips      = _extract_memory_ips(memory_finding)
    net_ips      = _extract_network_ips(network_finding)
    mem_procs    = _extract_proc_names(memory_finding)
    disk_exes    = _extract_disk_exes(disk_finding)
    net_domains  = _extract_network_domains(network_finding)
    bulk_domains = _extract_bulk_domains(disk_finding)
    mem_cmdlines = _extract_cmdlines(memory_finding)

    # ── Check 1: IP overlap memory ↔ network ─────────────────────────────
    overlap_ips = mem_ips & net_ips
    if overlap_ips:
        correlations.append(Correlation(
            title="IP addresses seen in both memory and PCAP",
            description=(
                "The following external IPs appeared in Volatility network connections "
                "AND in PCAP traffic, indicating active C2 or lateral-movement channels."
            ),
            severity="high",
            sources=["memory", "network"],
            evidence=sorted(overlap_ips)[:20],
            category="ip_overlap",
        ))

    # ── Check 2: Running processes corroborated on disk ───────────────────
    proc_on_disk = mem_procs & disk_exes
    if proc_on_disk:
        correlations.append(Correlation(
            title="Running processes corroborated on disk",
            description=(
                "These process names from memory were also found as executables on the "
                "disk image, confirming they are installed binaries."
            ),
            severity="low",
            sources=["memory", "disk"],
            evidence=sorted(proc_on_disk)[:20],
            category="process_file",
        ))

    # ── Check 3: Orphan processes (possible process hollowing) ────────────
    # FIX: whitelist comparison done in lowercase consistently
    _SYSTEM_PROCS = {
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "svchost.exe",
        "winlogon.exe", "explorer.exe", "idle", "registry",
    }
    orphan_procs = mem_procs - disk_exes - _SYSTEM_PROCS
    if orphan_procs:
        correlations.append(Correlation(
            title="Processes in memory with no matching executable on disk",
            description=(
                "These processes ran in memory but no matching .exe was found on disk. "
                "Possible process hollowing, fileless malware, or memory-resident payloads."
            ),
            severity="high",
            sources=["memory", "disk"],
            evidence=sorted(orphan_procs)[:20],
            category="process_hollowing",
        ))

    # ── Check 4: Domain overlap disk ↔ network DNS ───────────────────────
    domain_overlap = bulk_domains & net_domains
    if domain_overlap:
        correlations.append(Correlation(
            title="Domains found in both disk artefacts and network traffic",
            description=(
                "Domain names from the disk image were also observed as DNS queries in "
                "the PCAP, confirming active use."
            ),
            severity="medium",
            sources=["disk", "network"],
            evidence=sorted(domain_overlap)[:20],
            category="domain_overlap",
        ))

    # ── Check 5: Suspicious memory ports ─────────────────────────────────
    sus_mem_conns = _suspicious_memory_connections(memory_finding)
    if sus_mem_conns:
        correlations.append(Correlation(
            title="Memory network connections on anomalous ports",
            description=(
                "Volatility netscan found connections on ports commonly associated with "
                "remote access tools, C2 frameworks, or raw shells."
            ),
            severity="critical",
            sources=["memory"],
            evidence=sus_mem_conns[:20],
            category="suspicious_port",
        ))

    # ── Check 6: Obfuscated command lines ─────────────────────────────────
    obf_cmds = _detect_obfuscated_cmdlines(mem_cmdlines)
    if obf_cmds:
        correlations.append(Correlation(
            title="Obfuscated or encoded command lines in memory",
            description=(
                "Command-line arguments from Volatility contain Base64, PowerShell "
                "-EncodedCommand, or other obfuscation patterns."
            ),
            severity="critical",
            sources=["memory"],
            evidence=obf_cmds[:10],
            category="obfuscated_cmdline",
        ))

    # ── Check 7: Suspicious processes with active network connections ─────
    if memory_finding:
        yara_procs = {
            (p.get("ImageFileName") or p.get("Process") or "").lower()
            for p in memory_finding.suspicious_processes
        }
        active_owners = {
            (c.get("Owner") or c.get("Process") or "").lower()
            for c in (memory_finding.network_connections or [])
        }
        yara_net_overlap = yara_procs & active_owners - {""}
        if yara_net_overlap:
            correlations.append(Correlation(
                title="Suspicious processes with active network connections",
                description=(
                    "Processes flagged as suspicious (injection, anomalous PPID, or known "
                    "tool name) also hold active network connections — strong C2 indicator."
                ),
                severity="critical",
                sources=["memory"],
                evidence=sorted(yara_net_overlap)[:10],
                category="c2_process",
            ))

    logger.info("[CORR] %d correlation findings", len(correlations))
    return [asdict(c) for c in correlations]


# ─── Extraction helpers ───────────────────────────────────────────────────────

def _valid_external_ip(ip: str) -> bool:
    """Return True if ip is a valid, non-private IPv4 address."""
    if not ip:
        return False
    m = _IPV4_RE.match(ip)
    if not m:
        return False
    if not all(0 <= int(g) <= 255 for g in m.groups()):
        return False
    return not _PRIVATE_IP_RE.match(ip)


def _extract_memory_ips(mf) -> Set[str]:
    if not mf:
        return set()
    ips: Set[str] = set()
    for conn in (mf.network_connections or []):
        for key in ("ForeignAddr", "RemoteAddress"):
            raw = str(conn.get(key) or "")
            ip = raw.rsplit(":", 1)[0]
            if _valid_external_ip(ip):
                ips.add(ip)
    return ips


def _extract_network_ips(nf) -> Set[str]:
    if not nf:
        return set()
    return {ip for ip in nf.unique_ips if _valid_external_ip(ip)}


def _extract_proc_names(mf) -> Set[str]:
    if not mf:
        return set()
    return {
        (p.get("ImageFileName") or p.get("COMM") or "").lower().strip()
        for p in mf.processes
        if p.get("ImageFileName") or p.get("COMM")
    }


def _extract_disk_exes(df) -> Set[str]:
    if not df:
        return set()
    exes: Set[str] = set()
    for f in df.files:
        raw = str(f.get("name") or f.get("raw") or "")
        lower = raw.lower()
        if lower.endswith(".exe") or lower.endswith(".elf"):
            exes.add(lower.split("/")[-1].split("\\")[-1].strip())
    return exes


def _extract_network_domains(nf) -> Set[str]:
    if not nf:
        return set()
    domains = set(nf.unique_domains)
    domains.update(nf.tls_sni)
    return {d.lower() for d in domains}


def _extract_bulk_domains(df) -> Set[str]:
    if not df:
        return set()
    return {d.lower() for d in df.bulk_features.get("domain", []) if len(d) > 4}


def _extract_cmdlines(mf) -> List[str]:
    if not mf:
        return []
    return [
        str(c.get("Args") or c.get("CommandLine") or "")
        for c in mf.cmdlines
        if c.get("Args") or c.get("CommandLine")
    ]


_SUSPICIOUS_PORTS = {"4444", "1337", "31337", "6666", "6667", "9001", "9050", "8888"}


def _suspicious_memory_connections(mf) -> List[str]:
    if not mf:
        return []
    suspects = []
    for conn in (mf.network_connections or []):
        for key in ("ForeignAddr", "LocalAddr"):
            raw = str(conn.get(key) or "")
            parts = raw.rsplit(":", 1)
            port = parts[-1] if len(parts) > 1 else ""
            if port in _SUSPICIOUS_PORTS:
                owner = conn.get("Owner") or conn.get("Process") or "?"
                suspects.append(f"{raw} (owner: {owner})")
    return suspects


_OBFUSCATION_RE = re.compile(
    r"(-enc\w*|-encodedcommand|iex\s*\(|invoke-expression|frombase64|"
    r"downloadstring|hidden.*bypass|[A-Za-z0-9+/]{60,}={0,2})",
    re.I,
)


def _detect_obfuscated_cmdlines(cmdlines: List[str]) -> List[str]:
    return [cmd[:200] for cmd in cmdlines if _OBFUSCATION_RE.search(cmd)]
