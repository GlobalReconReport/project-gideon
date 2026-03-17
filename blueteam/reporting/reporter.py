"""
Reporter - HTML and PDF forensic intelligence report generation.

Bug-fixes applied:
  - Basic fallback renderer now HTML-escapes all user-controlled values (XSS fix)
  - truncate_str filter uses ASCII '...' not Unicode ellipsis (encoding safety)
  - Template name updated to dfir_report.html.j2
  - Jinja2 render wrapped in try/except with informative error message
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("dfir.reporter")

try:
    import jinja2
    _JINJA2 = True
except ImportError:
    _JINJA2 = False
    logger.warning("jinja2 not installed; HTML report will use basic fallback")

_HTML_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"}


def _esc(s: object) -> str:
    """HTML-escape a value for safe embedding in HTML attributes and text."""
    return "".join(_HTML_ESCAPES.get(c, c) for c in str(s or ""))


def generate(
    ctx,
    disk_finding,
    memory_finding,
    network_finding,
    timeline_result: Dict,
    ioc_result: Dict,
    correlations: List[Dict],
    templates_dir: str,
    output_dir: Optional[str] = None,
    tools: Optional[Dict] = None,
) -> Dict[str, str]:
    if output_dir is None:
        output_dir = str(Path(ctx.case_dir) / "reports")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in ctx.case_name)
    ts_str    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    html_path = Path(output_dir) / f"DFIR_{safe_name}_{ts_str}.html"
    pdf_path  = Path(output_dir) / f"DFIR_{safe_name}_{ts_str}.pdf"

    render_ctx = _build_render_context(
        ctx, disk_finding, memory_finding, network_finding,
        timeline_result, ioc_result, correlations,
    )

    if _JINJA2:
        try:
            _render_jinja2(templates_dir, render_ctx, html_path)
        except Exception as exc:
            logger.error("[RPT] Jinja2 render failed (%s); falling back to basic", exc)
            _render_basic(render_ctx, html_path)
    else:
        _render_basic(render_ctx, html_path)

    logger.info("[RPT] HTML report: %s", html_path)

    pdf_out = _render_pdf(html_path, pdf_path, tools or {})
    if pdf_out:
        logger.info("[RPT] PDF report: %s", pdf_out)
    else:
        logger.warning("[RPT] PDF skipped (no wkhtmltopdf or weasyprint found)")

    return {"html": str(html_path), "pdf": str(pdf_path) if pdf_out else None}


# ─── Render context ───────────────────────────────────────────────────────────

def _build_render_context(ctx, disk_finding, memory_finding, network_finding,
                           timeline_result, ioc_result, correlations) -> Dict[str, Any]:
    sev_counts: Dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    }
    for ioc in ioc_result.get("iocs", []):
        sev = ioc.get("severity", "info")
        if sev in sev_counts:
            sev_counts[sev] += 1

    exec_bullets: List[str] = []
    if disk_finding:
        exec_bullets.append(
            f"Disk image: {len(disk_finding.partitions)} partition(s), "
            f"{len(disk_finding.files):,} filesystem entries, "
            f"{sum(len(v) for v in disk_finding.bulk_features.values()):,} bulk_extractor features."
        )
    if memory_finding:
        exec_bullets.append(
            f"Memory (OS: {memory_finding.os_profile}): "
            f"{len(memory_finding.processes)} processes, "
            f"{len(memory_finding.network_connections)} connections, "
            f"{len(memory_finding.malfind_regions)} injected regions, "
            f"{len(memory_finding.suspicious_processes)} flagged processes."
        )
    if network_finding:
        exec_bullets.append(
            f"PCAP: {network_finding.packet_count:,} packets over "
            f"{network_finding.duration_sec:.1f}s, "
            f"{len(network_finding.unique_ips)} IPs, "
            f"{len(network_finding.unique_domains)} domains."
        )
    exec_bullets.append(
        f"Timeline: {timeline_result.get('total', 0):,} events "
        f"(disk={timeline_result.get('stats', {}).get('disk', 0):,}, "
        f"memory={timeline_result.get('stats', {}).get('memory', 0):,}, "
        f"network={timeline_result.get('stats', {}).get('network', 0):,})."
    )
    exec_bullets.append(
        f"IOCs: {ioc_result.get('total', 0)} unique indicators "
        f"({sev_counts['critical']} critical, {sev_counts['high']} high)."
    )
    exec_bullets.append(f"Cross-source correlations: {len(correlations)} finding(s).")

    return {
        "case_name":       ctx.case_name,
        "examiner":        ctx.examiner,
        "created_at":      ctx.created_at,
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "evidence":        [asdict(e) for e in ctx.evidence],
        "coc":             [asdict(c) for c in ctx.chain_of_custody[-50:]],
        "exec_bullets":    exec_bullets,
        "sev_counts":      sev_counts,
        "disk":            _disk_summary(disk_finding),
        "memory":          _memory_summary(memory_finding),
        "network":         _network_summary(network_finding),
        "timeline_events": timeline_result.get("events", []),
        "timeline_total":  timeline_result.get("total", 0),
        "iocs":            ioc_result.get("iocs", []),
        "ioc_total":       ioc_result.get("total", 0),
        "ioc_by_type":     ioc_result.get("by_type", {}),
        "correlations":    correlations,
    }


def _disk_summary(df) -> Dict:
    if not df:
        return {}
    return {
        "partitions":    df.partitions,
        "file_count":    len(df.files),
        "bulk_summary":  {k: len(v) for k, v in df.bulk_features.items()},
        "timeline_path": df.timeline_csv,
        "errors":        df.errors,
    }


def _memory_summary(mf) -> Dict:
    if not mf:
        return {}
    return {
        "os_profile":    mf.os_profile,
        "process_count": len(mf.processes),
        "processes":     mf.processes[:100],
        "cmdlines":      mf.cmdlines[:50],
        "net_conns":     mf.network_connections[:100],
        "malfind_count": len(mf.malfind_regions),
        "malfind":       mf.malfind_regions[:20],
        "suspicious":    mf.suspicious_processes[:50],
        "hives":         mf.registry_hives[:20],
        "errors":        mf.errors,
    }


def _network_summary(nf) -> Dict:
    if not nf:
        return {}
    return {
        "packet_count":     nf.packet_count,
        "duration_sec":     nf.duration_sec,
        "protocol_summary": nf.protocol_summary,
        "top_tcp_conns":    nf.conversations_tcp[:20],
        "dns_queries":      nf.dns_queries[:100],
        "http_requests":    nf.http_requests[:100],
        "tls_sni":          nf.tls_sni[:50],
        "unique_ips":       nf.unique_ips[:200],
        "suspicious":       nf.suspicious[:50],
        "bulk_summary":     {k: len(v) for k, v in nf.bulk_features.items()},
        "errors":           nf.errors,
    }


# ─── Rendering ────────────────────────────────────────────────────────────────

def _render_jinja2(templates_dir: str, ctx: Dict, out: Path) -> None:
    loader = jinja2.FileSystemLoader(templates_dir)
    env = jinja2.Environment(
        loader=loader,
        autoescape=jinja2.select_autoescape(["html"]),
    )
    # FIX: use ASCII '...' not Unicode ellipsis to avoid encoding issues
    env.filters["severity_class"] = lambda s: {
        "critical": "sev-critical", "high": "sev-high",
        "medium":   "sev-medium",   "low":  "sev-low",
    }.get(str(s).lower(), "sev-info")
    env.filters["truncate_str"] = lambda s, n=80: (
        (str(s)[:n] + "...") if len(str(s)) > n else str(s)
    )

    tmpl = env.get_template("dfir_report.html.j2")
    out.write_text(tmpl.render(**ctx), encoding="utf-8")


def _render_basic(ctx: Dict, out: Path) -> None:
    """Minimal fallback HTML — all values properly HTML-escaped (XSS fix)."""
    lines = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>DFIR Report - {_esc(ctx['case_name'])}</title>",
        "<style>body{font-family:monospace;background:#111;color:#eee;padding:2em}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #444;padding:6px}"
        ".c{color:#f44}.h{color:#f84}.m{color:#fa0}.l{color:#8f8}</style>",
        "</head><body>",
        f"<h1>DFIR Triage Report: {_esc(ctx['case_name'])}</h1>",
        f"<p>Examiner: {_esc(ctx['examiner'])} | Generated: {_esc(ctx['generated_at'])}</p>",
        "<h2>Executive Summary</h2><ul>",
    ]
    for b in ctx["exec_bullets"]:
        lines.append(f"<li>{_esc(b)}</li>")
    lines.append("</ul>")

    lines.append(
        "<h2>IOCs</h2>"
        "<table><tr><th>Type</th><th>Value</th><th>Source</th><th>Severity</th></tr>"
    )
    for ioc in ctx["iocs"][:500]:
        sev = _esc(ioc.get("severity", "info"))
        cls = {"critical": "c", "high": "h", "medium": "m", "low": "l"}.get(
            ioc.get("severity", ""), ""
        )
        lines.append(
            f"<tr class='{cls}'>"
            f"<td>{_esc(ioc.get('type'))}</td>"
            f"<td>{_esc(str(ioc.get('value', ''))[:80])}</td>"
            f"<td>{_esc(ioc.get('source'))}</td>"
            f"<td>{sev}</td></tr>"
        )
    lines.append("</table>")

    lines.append(
        "<h2>Timeline (top 500)</h2>"
        "<table><tr><th>Time</th><th>Source</th><th>Event</th><th>Severity</th></tr>"
    )
    for ev in ctx["timeline_events"][:500]:
        sev = _esc(ev.get("severity", "info"))
        cls = {"critical": "c", "high": "h", "medium": "m", "low": "l"}.get(
            ev.get("severity", ""), ""
        )
        lines.append(
            f"<tr class='{cls}'>"
            f"<td>{_esc(str(ev.get('timestamp', ''))[:19])}</td>"
            f"<td>{_esc(ev.get('source'))}</td>"
            f"<td>{_esc(str(ev.get('description', ''))[:100])}</td>"
            f"<td>{sev}</td></tr>"
        )
    lines.append("</table></body></html>")
    out.write_text("\n".join(lines), encoding="utf-8")


def _render_pdf(html_path: Path, pdf_path: Path, tools: Dict) -> Optional[str]:
    wk = tools.get("wkhtmltopdf", "wkhtmltopdf")
    if shutil.which(wk):
        try:
            subprocess.run(
                [wk, "--quiet", "--page-size", "A4",
                 "--margin-top", "15mm", "--margin-bottom", "15mm",
                 "--margin-left", "12mm", "--margin-right", "12mm",
                 str(html_path), str(pdf_path)],
                check=True, capture_output=True, timeout=120,
            )
            return str(pdf_path)
        except Exception as exc:
            logger.warning("[RPT] wkhtmltopdf failed: %s", exc)

    wp = tools.get("weasyprint", "weasyprint")
    if shutil.which(wp):
        try:
            subprocess.run([wp, str(html_path), str(pdf_path)],
                           check=True, capture_output=True, timeout=120)
            return str(pdf_path)
        except Exception as exc:
            logger.warning("[RPT] weasyprint CLI failed: %s", exc)

    try:
        import weasyprint as wp_mod
        wp_mod.HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return str(pdf_path)
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("[RPT] weasyprint API failed: %s", exc)

    return None
