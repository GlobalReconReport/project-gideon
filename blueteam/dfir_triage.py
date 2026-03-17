#!/usr/bin/env python3
"""
GIDEON LANTERN — Digital Forensics & Incident Response
=======================================================
Modular automated DFIR triage and timeline correlation toolkit.

Orchestrates:
  • Disk forensics    — SleuthKit (Autopsy engine), bulk_extractor, Plaso
  • Memory forensics  — Volatility 3
  • Network forensics — tshark (Wireshark CLI), bulk_extractor
  • Timeline          — unified sorted JSONL + in-report table
  • IOC scanning      — YARA rules + structured indicator extraction
  • Correlation       — cross-source set-intersection analysis
  • Reporting         — intelligence-style HTML + PDF report

Usage:
  python3 dfir_triage.py -c "Case-001" -e "J.Smith" \\
      --disk /evidence/disk.dd --memory /evidence/mem.dmp --pcap /evidence/cap.pcap

  python3 dfir_triage.py --check-tools
  python3 dfir_triage.py --light-mode --memory /evidence/mem.dmp -c "Quick-Triage"
"""

from __future__ import annotations

import argparse
import gc
import shutil
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# ── Project root on sys.path so all packages resolve ─────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from blueteam.acquisition  import evidence_handler as eh
from blueteam.artifacts    import disk_analyzer    as da
from blueteam.artifacts    import memory_analyzer  as ma
from blueteam.artifacts    import network_analyzer as na
from blueteam.timeline     import timeline_builder as tb
from blueteam.ioc_scanning import ioc_scanner      as ioc
from blueteam.artifacts    import correlator       as corr
from blueteam.reporting    import reporter         as rep
from shared                import config_loader
from shared                import logging as shared_logging

import logging
logger = logging.getLogger("dfir.main")

# ── Defaults ──────────────────────────────────────────────────────────────────
_DEFAULT_CONFIG    = _PROJECT_ROOT / "config"    / "dfir.yaml"
_DEFAULT_RULES     = _PROJECT_ROOT / "rules"     / "yara"
_DEFAULT_TEMPLATES = _PROJECT_ROOT / "templates"
_DEFAULT_OUTPUT    = Path.cwd() / "dfir_cases"

# ── ANSI colours ──────────────────────────────────────────────────────────────
_GOLD  = "\033[38;5;220m"
_BLUE  = "\033[38;5;39m"
_BOLD  = "\033[1m"
_DIM   = "\033[2m"
_RESET = "\033[0m"


# ─── Banner ───────────────────────────────────────────────────────────────────

def print_lantern_banner() -> None:
    g = _GOLD + _BOLD
    b = _BLUE + _BOLD
    d = _DIM
    r = _RESET
    print(f"""
{b}  ╔══════════════════════════════════════════════════════════╗
  ║                                                          ║
  ║  {g}  ██████╗ ██╗██████╗ ███████╗ ██████╗ ███╗  ██╗        {b}║
  ║  {g}  ██╔════╝ ██║██╔══██╗██╔════╝██╔═══██╗████╗ ██║        {b}║
  ║  {g}  ██║  ███╗██║██║  ██║█████╗  ██║   ██║██╔██╗██║        {b}║
  ║  {g}  ██║   ██║██║██║  ██║██╔══╝  ██║   ██║██║╚████║        {b}║
  ║  {g}  ╚██████╔╝██║██████╔╝███████╗╚██████╔╝██║ ╚███║        {b}║
  ║  {g}   ╚═════╝ ╚═╝╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚══╝        {b}║
  ║                                                          ║
  ║  {g}L A N T E R N{b}  {d}// Digital Forensics & Incident Response{r}{b}  ║
  ║                                                          ║
  ╚══════════════════════════════════════════════════════════╝{r}
""")


# ─── Tool check ───────────────────────────────────────────────────────────────

REQUIRED_TOOLS = {
    "vol":             "Volatility 3 (memory analysis)",
    "log2timeline.py": "Plaso log2timeline (disk timeline)",
    "psort.py":        "Plaso psort (timeline export)",
    "bulk_extractor":  "bulk_extractor (feature extraction)",
    "tshark":          "tshark / Wireshark CLI (PCAP analysis)",
    "mmls":            "SleuthKit mmls / Autopsy backend (partition table)",
    "fls":             "SleuthKit fls / Autopsy backend (file listing)",
    "yara":            "YARA (malware/IOC scanning)",
    "wkhtmltopdf":     "wkhtmltopdf (PDF generation)",
}


def check_tools() -> Dict[str, bool]:
    results = {}
    print("\n  Tool Availability Check\n  " + "─" * 40)
    for binary, desc in REQUIRED_TOOLS.items():
        found = shutil.which(binary) is not None
        results[binary] = found
        status = f"\033[32m✓\033[0m" if found else f"\033[31m✗\033[0m"
        print(f"  {status}  {binary:<22} {desc}")
    print()
    return results


# ─── Config ───────────────────────────────────────────────────────────────────

def _tools_from_config(cfg: Dict) -> Dict[str, str]:
    defaults = {
        "volatility":   "vol",
        "log2timeline": "log2timeline.py",
        "psort":        "psort.py",
        "bulk_extractor": "bulk_extractor",
        "tshark":       "tshark",
        "mmls":         "mmls",
        "fls":          "fls",
        "tsk_recover":  "tsk_recover",
        "yara":         "yara",
        "wkhtmltopdf":  "wkhtmltopdf",
        "weasyprint":   "weasyprint",
    }
    defaults.update(cfg.get("tools", {}))
    return defaults


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dfir_triage.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            GIDEON LANTERN — DFIR triage toolkit for Kali Linux.
            At least one of --disk / --memory / --pcap is required.
        """),
    )
    ev = p.add_argument_group("Evidence Inputs")
    ev.add_argument("--disk",   metavar="IMAGE",   help="Disk image (dd, E01, VMDK, ...)")
    ev.add_argument("--memory", metavar="DUMP",    help="Memory dump (raw, LiME, vmem, ...)")
    ev.add_argument("--pcap",   metavar="CAPTURE", help="Network capture (PCAP / PCAPng)")

    md = p.add_argument_group("Case Metadata")
    md.add_argument("-c", "--case",     default="DFIR_Case", help="Case name")
    md.add_argument("-e", "--examiner", default="Analyst",   help="Examiner name")
    md.add_argument("-o", "--output",   default=str(_DEFAULT_OUTPUT),
                    help=f"Base output directory (default: {_DEFAULT_OUTPUT})")
    md.add_argument("--notes", default="", help="Free-text notes in the report")

    ao = p.add_argument_group("Analysis Options")
    ao.add_argument("--yara-rules",  default=str(_DEFAULT_RULES),
                    help="Directory containing YARA rule files")
    ao.add_argument("--config",      default=str(_DEFAULT_CONFIG),
                    help="Path to dfir.yaml")
    ao.add_argument("--vol-plugins", nargs="*", metavar="PLUGIN",
                    help="Override Volatility plugins list")
    ao.add_argument("--timeline-limit", type=int, default=5000,
                    help="Max timeline events in report (default: 5000)")
    ao.add_argument("--skip-disk",    action="store_true")
    ao.add_argument("--skip-memory",  action="store_true")
    ao.add_argument("--skip-network", action="store_true")
    ao.add_argument("--skip-yara",    action="store_true")
    ao.add_argument("--no-pdf",       action="store_true")
    ao.add_argument(
        "--light-mode", action="store_true",
        help=(
            "Live USB / low-RAM mode: skips Volatility memory analysis "
            "(most RAM-intensive step). All other modules run normally."
        ),
    )

    ut = p.add_argument_group("Utilities")
    ut.add_argument("--check-tools", action="store_true",
                    help="Check tool availability and exit")
    ut.add_argument("-v", "--verbose", action="store_true")

    return p


# ─── Pipeline ─────────────────────────────────────────────────────────────────

def run_pipeline(args: argparse.Namespace, cfg: Dict) -> int:
    tools        = _tools_from_config(cfg)
    analysis     = cfg.get("analysis", {})
    tool_timeout = analysis.get("tool_timeout", 3600)

    # 0 ── Case init (logging to stdout only until case_dir is known) ─────────
    ctx = eh.initialise_case(
        case_name=args.case,
        examiner=args.examiner,
        base_dir=Path(args.output),
    )
    # FIX: single logging setup call — now includes file handler for case log
    shared_logging.setup(
        log_file=str(Path(ctx.case_dir) / "logs" / "dfir_triage.log"),
        verbose=args.verbose,
    )
    global logger
    logger = logging.getLogger("dfir.main")

    logger.info("=" * 70)
    logger.info("GIDEON LANTERN  —  Case: %s  |  Examiner: %s", args.case, args.examiner)
    logger.info("Case directory: %s", ctx.case_dir)
    if args.light_mode:
        logger.info("LIGHT MODE: Volatility memory analysis will be skipped")
    logger.info("=" * 70)

    # 1 ── Evidence ingestion ─────────────────────────────────────────────────
    evidence_paths: List[Path] = []
    if args.disk:   evidence_paths.append(Path(args.disk))
    if args.memory: evidence_paths.append(Path(args.memory))
    if args.pcap:   evidence_paths.append(Path(args.pcap))

    if not evidence_paths:
        logger.error("No evidence files specified.")
        return 1

    eh.ingest_evidence(ctx, evidence_paths)
    eh.save_coc_log(ctx)

    disk_finding    = None
    memory_finding  = None
    network_finding = None

    # 2 ── Disk ───────────────────────────────────────────────────────────────
    if args.disk and not args.skip_disk:
        disk_ev = eh.get_evidence_by_type(ctx, "disk")
        if disk_ev:
            logger.info("[DISK] Starting disk analysis ...")
            disk_finding = da.analyse(
                image_path=disk_ev[0].path,
                case_dir=ctx.case_dir,
                tools=tools,
                tool_timeout=tool_timeout,
            )
            eh.save_coc_log(ctx)
            gc.collect()
        else:
            logger.warning("[DISK] No disk evidence detected (check extension/magic)")

    # 3 ── Memory ─────────────────────────────────────────────────────────────
    skip_memory = args.skip_memory or args.light_mode
    if args.memory and not skip_memory:
        mem_ev = eh.get_evidence_by_type(ctx, "memory")
        if not mem_ev:
            mem_ev = [e for e in ctx.evidence
                      if Path(args.memory).resolve() == Path(e.path).resolve()]
        if mem_ev:
            logger.info("[MEM] Starting memory analysis ...")
            memory_finding = ma.analyse(
                memory_path=mem_ev[0].path,
                case_dir=ctx.case_dir,
                tools=tools,
                plugin_list=args.vol_plugins,
                tool_timeout=tool_timeout,
            )
            eh.save_coc_log(ctx)
            gc.collect()
        else:
            logger.warning("[MEM] Could not match memory evidence file")
    elif args.light_mode and args.memory:
        logger.info("[MEM] Skipped (--light-mode)")

    # 4 ── Network ────────────────────────────────────────────────────────────
    if args.pcap and not args.skip_network:
        pcap_ev = eh.get_evidence_by_type(ctx, "pcap")
        if pcap_ev:
            logger.info("[NET] Starting network analysis ...")
            network_finding = na.analyse(
                pcap_path=pcap_ev[0].path,
                case_dir=ctx.case_dir,
                tools=tools,
                tool_timeout=tool_timeout,
            )
            eh.save_coc_log(ctx)
            gc.collect()
        else:
            logger.warning("[NET] No PCAP evidence detected")

    # 5 ── Timeline ───────────────────────────────────────────────────────────
    logger.info("[TL] Building unified forensic timeline ...")
    timeline_result = tb.build(
        disk_finding=disk_finding,
        memory_finding=memory_finding,
        network_finding=network_finding,
        case_dir=ctx.case_dir,
        report_limit=args.timeline_limit,
    )
    gc.collect()

    # 6 ── IOC scan ───────────────────────────────────────────────────────────
    if not args.skip_yara:
        logger.info("[IOC] Running IOC extraction and YARA scan ...")
        ioc_result = ioc.scan(
            disk_finding=disk_finding,
            memory_finding=memory_finding,
            network_finding=network_finding,
            case_dir=ctx.case_dir,
            rules_dir=args.yara_rules,
            tool_timeout=analysis.get("yara_timeout", 60),
        )
    else:
        ioc_result = {"iocs": [], "total": 0, "by_type": {}}
    gc.collect()

    # 7 ── Correlation ────────────────────────────────────────────────────────
    logger.info("[CORR] Running cross-source correlation ...")
    correlations = corr.correlate(
        disk_finding=disk_finding,
        memory_finding=memory_finding,
        network_finding=network_finding,
    )

    # 8 ── Integrity re-check ─────────────────────────────────────────────────
    logger.info("[INTEG] Re-verifying evidence integrity ...")
    integrity_ok = eh.verify_integrity(ctx)
    if not integrity_ok:
        logger.error("!!! INTEGRITY FAILURE — evidence hash mismatch detected !!!")
    eh.save_coc_log(ctx)

    # 9 ── Report ─────────────────────────────────────────────────────────────
    logger.info("[RPT] Generating report ...")
    report_paths = rep.generate(
        ctx=ctx,
        disk_finding=disk_finding,
        memory_finding=memory_finding,
        network_finding=network_finding,
        timeline_result=timeline_result,
        ioc_result=ioc_result,
        correlations=correlations,
        templates_dir=str(_DEFAULT_TEMPLATES),
        output_dir=str(Path(ctx.case_dir) / "reports"),
        tools=None if args.no_pdf else tools,
    )

    _print_summary(ctx, timeline_result, ioc_result, correlations, report_paths)
    return 0


def _print_summary(ctx, timeline_result, ioc_result, correlations, report_paths) -> None:
    sev: Dict[str, int] = {}
    for item in ioc_result.get("iocs", []):
        s = item.get("severity", "")
        sev[s] = sev.get(s, 0) + 1

    sep = "═" * 70
    print(f"\n{sep}")
    print(f"  GIDEON LANTERN — {ctx.case_name} — COMPLETE")
    print(sep)
    print(f"  Case directory : {ctx.case_dir}")
    print(f"  HTML report    : {report_paths['html']}")
    if report_paths.get("pdf"):
        print(f"  PDF report     : {report_paths['pdf']}")
    print(f"  Timeline events: {timeline_result.get('total', 0):,}")
    print(f"  IOCs found     : {ioc_result.get('total', 0):,}  "
          f"(critical={sev.get('critical', 0)}  high={sev.get('high', 0)})")
    print(f"  Correlations   : {len(correlations)}")
    print(sep + "\n")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    # Initial logging to stdout only (file handler added after case_dir is known)
    shared_logging.setup(verbose=getattr(args, "verbose", False))

    if args.check_tools:
        print_lantern_banner()
        check_tools()
        return 0

    if not any([args.disk, args.memory, args.pcap]):
        parser.print_help()
        print("\nError: at least one of --disk / --memory / --pcap is required.\n")
        return 1

    print_lantern_banner()
    cfg = config_loader.load_yaml(args.config)

    try:
        return run_pipeline(args, cfg)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        return 130
    except Exception as exc:
        logging.getLogger("dfir.main").exception("Unhandled exception: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
