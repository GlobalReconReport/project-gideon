"""
IOC Scanner - YARA scanning + indicator extraction.

Bug-fixes applied:
  - Large file skip now emits a warning with the file name and size
  - _iocs_from_memory: hash validation uses proper hex check before yield
  - _value_severity: PII types now correctly return "high"
"""

import json
import logging
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Generator, List, Optional, Set

logger = logging.getLogger("dfir.ioc")

_PRIVATE_IP_RE = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80:)"
)
_IPV4_RE   = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_MD5_RE    = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE   = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_URL_RE    = re.compile(r"https?://[^\s\"'<>]{4,200}")

_SKIP_DOMAINS = {
    "localhost", "local", "example.com", "microsoft.com",
    "windows.com", "windowsupdate.com", "msftconnecttest.com",
    "dns.msftncsi.com", "time.windows.com",
}

_BULK_TO_IOC = {
    "ip":         "ip",
    "domain":     "domain",
    "url":        "url",
    "email":      "email",
    "creditcard": "pii",
    "hashes":     "md5",
}

_MAX_YARA_FILE_SIZE = 50 * 1024 * 1024   # 50 MB
_MAX_BE_FILE_SIZE   = 10 * 1024 * 1024   # 10 MB


@dataclass
class IOC:
    type: str
    value: str
    source: str
    context: str
    severity: str


def scan(
    disk_finding,
    memory_finding,
    network_finding,
    case_dir: str,
    rules_dir: str,
    tool_timeout: int = 60,
) -> Dict:
    ioc_dir = Path(case_dir) / "iocs"
    ioc_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = ioc_dir / "iocs.jsonl"
    seen: Set[str] = set()
    total = 0
    by_type: Dict[str, int] = {}
    TOP_N = 2000
    report_iocs: List[Dict] = []

    def _emit(ioc: IOC) -> None:
        nonlocal total
        key = f"{ioc.type}:{ioc.value}"
        if key in seen:
            return
        seen.add(key)
        total += 1
        by_type[ioc.type] = by_type.get(ioc.type, 0) + 1
        fh.write(json.dumps(asdict(ioc)) + "\n")
        if len(report_iocs) < TOP_N:
            report_iocs.append(asdict(ioc))

    with jsonl_path.open("w", encoding="utf-8") as fh:
        rules_path = Path(rules_dir) / "default.yar"
        if rules_path.exists():
            scan_targets = _collect_scan_targets(disk_finding, memory_finding, case_dir)
            for ioc_item in _yara_scan(scan_targets, rules_path, ioc_dir, tool_timeout):
                _emit(ioc_item)

        if disk_finding:
            for ioc_item in _iocs_from_bulk_features(disk_finding.bulk_features, "disk"):
                _emit(ioc_item)

        if network_finding:
            for ioc_item in _iocs_from_bulk_features(network_finding.bulk_features, "network"):
                _emit(ioc_item)
            for ioc_item in _iocs_from_network(network_finding):
                _emit(ioc_item)

        if memory_finding:
            for ioc_item in _iocs_from_memory(memory_finding):
                _emit(ioc_item)

    logger.info("[IOC] Total unique IOCs: %d  (YARA: %d)", total, by_type.get("yara_match", 0))
    return {
        "jsonl_path": str(jsonl_path),
        "iocs":       report_iocs,
        "total":      total,
        "by_type":    by_type,
    }


# ─── YARA ─────────────────────────────────────────────────────────────────────

def _collect_scan_targets(disk_finding, memory_finding, case_dir: str) -> List[Path]:
    targets: List[Path] = []
    if disk_finding and disk_finding.recovered_dir:
        rd = Path(disk_finding.recovered_dir)
        if rd.exists():
            for p in rd.rglob("*"):
                if p.is_file():
                    sz = p.stat().st_size
                    if sz > _MAX_YARA_FILE_SIZE:
                        logger.warning(
                            "[IOC] Skipping large file for YARA scan: %s (%.1f MB)",
                            p.name, sz / 1_048_576,
                        )
                    else:
                        targets.append(p)
    mem_dir = Path(case_dir) / "memory"
    if mem_dir.exists():
        targets += list(mem_dir.glob("*.txt"))
    be_disk = Path(case_dir) / "disk" / "bulk_extractor"
    if be_disk.exists():
        for p in be_disk.glob("*.txt"):
            if p.stat().st_size <= _MAX_BE_FILE_SIZE:
                targets.append(p)
            else:
                logger.warning("[IOC] Skipping large bulk_extractor file: %s", p.name)
    return targets[:500]


def _yara_scan(
    targets: List[Path],
    rules_path: Path,
    out_dir: Path,
    timeout: int,
) -> Generator[IOC, None, None]:
    yara_log = out_dir / "yara_matches.txt"
    yara_bin = "yara"
    yara_found = True

    for target in targets:
        if not target.exists() or target.stat().st_size == 0:
            continue
        if not yara_found:
            return
        try:
            result = subprocess.run(
                [yara_bin, "--no-warnings", str(rules_path), str(target)],
                capture_output=True, text=True, timeout=timeout,
            )
            if result.stdout.strip():
                with yara_log.open("a") as fh:
                    fh.write(result.stdout)
                for line in result.stdout.splitlines():
                    m = re.match(r"^(\S+)\s+(.+)$", line.strip())
                    if m:
                        rule_name = m.group(1)
                        yield IOC(
                            type="yara_match",
                            value=rule_name,
                            source="yara",
                            context=f"File: {Path(m.group(2)).name}",
                            severity=_yara_severity(rule_name),
                        )
        except FileNotFoundError:
            logger.warning("[IOC] yara binary not found; skipping YARA scan")
            yara_found = False
        except subprocess.TimeoutExpired:
            logger.warning("[IOC] yara timeout on: %s", target.name)


def _yara_severity(rule_name: str) -> str:
    low = rule_name.lower()
    if any(k in low for k in ("c2", "cobaltstrike", "mimikatz", "meterpreter", "webshell")):
        return "critical"
    if any(k in low for k in ("backdoor", "credential", "persistence", "lateral")):
        return "high"
    if any(k in low for k in ("packer", "recon", "exfil")):
        return "medium"
    return "low"


# ─── bulk_extractor feature IOCs ─────────────────────────────────────────────

def _iocs_from_bulk_features(features: Dict[str, List[str]], source: str
                              ) -> Generator[IOC, None, None]:
    for feat_type, values in features.items():
        ioc_type = _BULK_TO_IOC.get(feat_type, feat_type)
        for val in values:
            val = val.strip()
            if not val:
                continue
            if ioc_type == "ip" and _PRIVATE_IP_RE.match(val):
                continue
            if ioc_type == "domain" and val.lower() in _SKIP_DOMAINS:
                continue
            yield IOC(
                type=ioc_type,
                value=val[:512],
                source=source,
                context=f"bulk_extractor:{feat_type}",
                severity=_value_severity(ioc_type, val),
            )


# ─── Memory IOCs ──────────────────────────────────────────────────────────────

def _iocs_from_memory(mf) -> Generator[IOC, None, None]:
    for proc in mf.suspicious_processes:
        name = str(proc.get("ImageFileName") or proc.get("Process") or "?")
        yield IOC(
            type="process", value=name, source="memory",
            context=proc.get("reason", ""),
            severity=proc.get("severity", "medium"),
        )
    for conn in mf.network_connections:
        remote = str(conn.get("ForeignAddr") or conn.get("RemoteAddress") or "")
        ip_part = remote.rsplit(":", 1)[0] if ":" in remote else remote
        if ip_part and not _PRIVATE_IP_RE.match(ip_part) and _IPV4_RE.match(ip_part):
            yield IOC(
                type="ip", value=ip_part, source="memory",
                context=f"Volatility netscan: {remote}",
                severity="medium",
            )
    for h in mf.hashes:
        for key in ("NT", "LM", "Hash"):
            val = str(h.get(key, "")).strip()
            # FIX: validate it's a real 32-char hex before yielding
            if val and _MD5_RE.match(val) and val != "aad3b435b51404eeaad3b435b51404ee":
                yield IOC(
                    type="md5", value=val, source="memory",
                    context=f"hashdump: {h.get('User','?')}",
                    severity="high",
                )


# ─── Network IOCs ─────────────────────────────────────────────────────────────

def _iocs_from_network(nf) -> Generator[IOC, None, None]:
    for ip in nf.unique_ips:
        if not _PRIVATE_IP_RE.match(ip):
            yield IOC(type="ip", value=ip, source="network",
                      context="tshark", severity="low")
    for domain in nf.unique_domains:
        if domain.lower() not in _SKIP_DOMAINS:
            yield IOC(type="domain", value=domain, source="network",
                      context="dns_query", severity="low")
    for req in nf.http_requests:
        url = f"http://{req.get('host','')}{req.get('uri','')}"
        if len(url) > 10:
            yield IOC(type="url", value=url[:512], source="network",
                      context="http_request", severity="low")
    for sni in nf.tls_sni:
        yield IOC(type="domain", value=sni, source="network",
                  context="tls_sni", severity="low")
    for sus in nf.suspicious:
        yield IOC(
            type=sus.get("type", "network"),
            value=sus.get("detail", "?")[:256],
            source="network",
            context="suspicious_traffic",
            severity=sus.get("severity", "medium"),
        )


# ─── Severity helpers ─────────────────────────────────────────────────────────

def _value_severity(ioc_type: str, value: str) -> str:
    if ioc_type in ("pii", "creditcard"):
        return "high"    # FIX: was returning "high" but check was wrong; now consistent
    if ioc_type in ("md5", "sha1", "sha256"):
        return "medium"
    return "info"
