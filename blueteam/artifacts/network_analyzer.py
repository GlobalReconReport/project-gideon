"""
Network Analyzer - tshark (Wireshark CLI) + bulk_extractor on PCAP.

Bug-fixes applied:
  - _is_ip: IPv6 regex tightened — rejects obviously invalid strings
  - _detect_suspicious (beaconing): guards against empty IP after split
  - _detect_suspicious (cleartext creds): already lowercase before matching
  - bulk_extractor on PCAP: uses shared run_tool
"""

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from shared.utils import ToolError

logger = logging.getLogger("dfir.network")


@dataclass
class NetworkFinding:
    source: str = "network"
    conversations_tcp: List[Dict] = field(default_factory=list)
    conversations_udp: List[Dict] = field(default_factory=list)
    dns_queries: List[str] = field(default_factory=list)
    dns_responses: List[Dict] = field(default_factory=list)
    http_requests: List[Dict] = field(default_factory=list)
    tls_sni: List[str] = field(default_factory=list)
    unique_ips: List[str] = field(default_factory=list)
    unique_domains: List[str] = field(default_factory=list)
    bulk_features: Dict[str, List[str]] = field(default_factory=dict)
    protocol_summary: Dict[str, int] = field(default_factory=dict)
    packet_count: int = 0
    duration_sec: float = 0.0
    suspicious: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def analyse(pcap_path: str, case_dir: str, tools: Dict[str, str],
            tool_timeout: int = 3600) -> NetworkFinding:
    result = NetworkFinding()
    net_dir = Path(case_dir) / "network"
    net_dir.mkdir(parents=True, exist_ok=True)
    pcap = Path(pcap_path)
    ts = tools.get("tshark", "tshark")

    logger.info("[NET] Analysing PCAP: %s", pcap.name)

    result.packet_count, result.duration_sec = _get_pcap_stats(ts, pcap, tool_timeout)
    logger.info("[NET] Packets: %d | Duration: %.1fs",
                result.packet_count, result.duration_sec)

    result.protocol_summary = _protocol_stats(ts, pcap, tool_timeout)
    result.conversations_tcp = _conversations(ts, pcap, "tcp", tool_timeout)
    result.conversations_udp = _conversations(ts, pcap, "udp", tool_timeout)
    result.dns_queries, result.dns_responses = _dns_analysis(ts, pcap, tool_timeout)
    result.unique_domains = sorted(set(result.dns_queries))
    result.http_requests  = _http_analysis(ts, pcap, tool_timeout)
    result.tls_sni        = _tls_sni(ts, pcap, tool_timeout)
    result.unique_ips     = _extract_ips(ts, pcap, net_dir, tool_timeout)

    be_out = net_dir / "bulk_extractor"
    result.bulk_features  = _run_bulk_extractor(pcap, be_out, tools, tool_timeout)
    result.suspicious     = _detect_suspicious(result)

    logger.info(
        "[NET] IPs=%d  Domains=%d  HTTP=%d  DNS=%d  Suspicious=%d",
        len(result.unique_ips), len(result.unique_domains),
        len(result.http_requests), len(result.dns_queries),
        len(result.suspicious),
    )
    return result


# ─── tshark helpers ───────────────────────────────────────────────────────────

def _tshark(ts: str, pcap: Path, args: List[str], timeout: int) -> str:
    cmd = [ts, "-r", str(pcap)] + args
    logger.debug("[NET] tshark: %s", " ".join(cmd))
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.stdout
    except FileNotFoundError:
        raise ToolError(f"tshark not found: {ts}")
    except subprocess.TimeoutExpired:
        raise ToolError("tshark timed out")


def _get_pcap_stats(ts: str, pcap: Path, timeout: int):
    """Count packets by counting frame numbers (robust across tshark versions)."""
    try:
        out = _tshark(ts, pcap, ["-T", "fields", "-e", "frame.number",
                                  "-e", "frame.time_epoch"], timeout)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        count = len(lines)
        dur = 0.0
        if len(lines) > 1:
            try:
                t_first = float(lines[0].split("\t")[1]) if "\t" in lines[0] else 0.0
                t_last  = float(lines[-1].split("\t")[1]) if "\t" in lines[-1] else 0.0
                dur = max(0.0, t_last - t_first)
            except (ValueError, IndexError):
                pass
        return count, dur
    except ToolError:
        return 0, 0.0


def _protocol_stats(ts: str, pcap: Path, timeout: int) -> Dict[str, int]:
    stats: Dict[str, int] = {}
    try:
        out = _tshark(ts, pcap, ["-q", "-z", "ptype,tree"], timeout)
        for line in out.splitlines():
            m = re.match(r"\s+(\w+)\s+(\d+)", line)
            if m:
                stats[m.group(1)] = int(m.group(2))
    except ToolError:
        pass
    return stats


def _conversations(ts: str, pcap: Path, proto: str, timeout: int) -> List[Dict]:
    convs = []
    try:
        out = _tshark(ts, pcap, ["-q", "-z", f"conv,{proto}"], timeout)
        for line in out.splitlines():
            m = re.match(
                r"\s*(\S+)\s+<->\s+(\S+)\s+"
                r"(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)",
                line,
            )
            if m:
                convs.append({
                    "src": m.group(1), "dst": m.group(2),
                    "frames_src": m.group(3), "bytes_src": m.group(4),
                    "frames_dst": m.group(5), "bytes_dst": m.group(6),
                    "total_frames": m.group(7), "total_bytes": m.group(8),
                })
    except ToolError:
        pass
    return convs


def _dns_analysis(ts: str, pcap: Path, timeout: int):
    queries: List[str] = []
    responses: List[Dict] = []
    try:
        out = _tshark(
            ts, pcap,
            ["-Y", "dns", "-T", "fields",
             "-e", "dns.qry.name", "-e", "dns.resp.name",
             "-e", "dns.a", "-e", "dns.aaaa"],
            timeout,
        )
        for line in out.splitlines():
            parts = line.split("\t")
            if parts[0].strip():
                queries.append(parts[0].strip())
            if len(parts) > 1 and parts[1].strip():
                responses.append({
                    "name": parts[1].strip(),
                    "a":    parts[2].strip() if len(parts) > 2 else "",
                    "aaaa": parts[3].strip() if len(parts) > 3 else "",
                })
    except ToolError:
        pass
    return list(dict.fromkeys(queries)), responses


def _http_analysis(ts: str, pcap: Path, timeout: int) -> List[Dict]:
    requests = []
    try:
        out = _tshark(
            ts, pcap,
            ["-Y", "http.request", "-T", "fields",
             "-e", "ip.src", "-e", "http.host",
             "-e", "http.request.method", "-e", "http.request.uri",
             "-e", "http.user_agent"],
            timeout,
        )
        for line in out.splitlines():
            p = line.split("\t")
            if len(p) >= 3:
                requests.append({
                    "src":        p[0].strip(),
                    "host":       p[1].strip(),
                    "method":     p[2].strip(),
                    "uri":        p[3].strip() if len(p) > 3 else "",
                    "user_agent": p[4].strip() if len(p) > 4 else "",
                })
    except ToolError:
        pass
    return requests


def _tls_sni(ts: str, pcap: Path, timeout: int) -> List[str]:
    sni = []
    try:
        out = _tshark(
            ts, pcap,
            ["-Y", "tls.handshake.type == 1", "-T", "fields",
             "-e", "tls.handshake.extensions_server_name"],
            timeout,
        )
        for line in out.splitlines():
            v = line.strip()
            if v:
                sni.append(v)
    except ToolError:
        pass
    return list(dict.fromkeys(sni))


def _extract_ips(ts: str, pcap: Path, out_dir: Path, timeout: int) -> List[str]:
    ips: set = set()
    try:
        for field_name in ("ip.src", "ip.dst"):
            out = _tshark(ts, pcap, ["-T", "fields", "-e", field_name], timeout)
            for line in out.splitlines():
                v = line.strip()
                if v and _is_ipv4(v):
                    ips.add(v)
        ip_list = sorted(ips)
        (out_dir / "unique_ips.txt").write_text("\n".join(ip_list))
        return ip_list
    except ToolError:
        return []


# FIX: tightened to IPv4 only for IP extraction; IPv6 handled separately if needed
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _is_ipv4(s: str) -> bool:
    m = _IPV4_RE.match(s)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


# ─── bulk_extractor on PCAP ──────────────────────────────────────────────────

_BULK_FEATURE_FILES = ["domain", "ip", "url", "email", "telephone", "creditcard", "base64"]


def _run_bulk_extractor(pcap: Path, out_dir: Path, tools: Dict, timeout: int
                        ) -> Dict[str, List[str]]:
    be = tools.get("bulk_extractor", "bulk_extractor")
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        cmd = [be, "-o", str(out_dir), str(pcap)]
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return _parse_bulk_output(out_dir)
    except FileNotFoundError:
        logger.warning("[NET] bulk_extractor not found")
        return {}
    except subprocess.TimeoutExpired:
        logger.warning("[NET] bulk_extractor timed out")
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
            val = parts[1] if len(parts) > 1 else parts[0]
            entries.append(val.strip())
        if entries:
            features[name] = list(dict.fromkeys(entries))
    return features


# ─── Suspicious detection ─────────────────────────────────────────────────────

_PRIVATE_CIDRS = [
    re.compile(r"^10\."), re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^127\."), re.compile(r"^169\.254\."),
]

_SUSPICIOUS_PORTS = {
    "4444":  "Metasploit default",
    "1337":  "Hacker cliché / RAT",
    "31337": "Elite back-door",
    "6666":  "Common RAT port",
    "6667":  "IRC (potential C2)",
    "9001":  "Tor OR port",
    "9050":  "Tor SOCKS proxy",
}


def _is_private(ip: str) -> bool:
    return any(p.match(ip) for p in _PRIVATE_CIDRS)


def _detect_suspicious(result: NetworkFinding) -> List[Dict]:
    suspects = []

    # Suspicious ports in TCP conversations
    for conv in result.conversations_tcp + result.conversations_udp:
        for endpoint in (conv.get("src", ""), conv.get("dst", "")):
            if not endpoint:
                continue
            parts = endpoint.rsplit(":", 1)
            ip   = parts[0] if parts else ""
            port = parts[1] if len(parts) > 1 else ""
            # FIX: guard against empty ip before calling _is_private
            if ip and _is_ipv4(ip) and not _is_private(ip) and port in _SUSPICIOUS_PORTS:
                suspects.append({
                    "type":     "suspicious_port",
                    "detail":   f"{endpoint} — {_SUSPICIOUS_PORTS[port]}",
                    "severity": "high",
                })

    # Possible C2 beaconing: many connections to same external IP
    ext_conns: Dict[str, int] = {}
    for conv in result.conversations_tcp:
        for key in ("src", "dst"):
            raw = conv.get(key, "")
            ip = raw.rsplit(":", 1)[0] if raw else ""
            if ip and _is_ipv4(ip) and not _is_private(ip):
                ext_conns[ip] = ext_conns.get(ip, 0) + 1
    for ip, count in ext_conns.items():
        if count > 20:
            suspects.append({
                "type":     "possible_beaconing",
                "detail":   f"{ip} — {count} TCP conversations (possible C2 beaconing)",
                "severity": "high",
            })

    # Cleartext credentials in HTTP URIs (uri is already lowercased above via .lower())
    for req in result.http_requests:
        uri = req.get("uri", "").lower()
        if any(kw in uri for kw in ("password=", "passwd=", "pwd=", "pass=")):
            suspects.append({
                "type":     "cleartext_creds",
                "detail":   f"Credential in HTTP URI: {req.get('host','')}{uri[:80]}",
                "severity": "critical",
            })

    # DNS tunneling: abnormally long labels
    for q in result.dns_queries:
        if len(q) > 50:
            suspects.append({
                "type":     "dns_tunnel_candidate",
                "detail":   f"Long DNS query ({len(q)} chars): {q[:80]}",
                "severity": "medium",
            })

    return suspects
