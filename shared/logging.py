"""
Shared logging setup used by both redteam and blueteam tools.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


def setup(
    log_file: Optional[str] = None,
    verbose: bool = False,
) -> None:
    """
    Configure root logging.  Safe to call twice — the second call uses
    force=True so handlers are replaced rather than duplicated.
    """
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list = [logging.StreamHandler(sys.stdout)]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)-18s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=handlers,
        force=True,   # Python 3.8+ — replaces handlers on re-call
    )
