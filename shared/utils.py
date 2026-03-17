"""
Shared subprocess utilities for forensic tool invocation.
Used by blueteam modules; redteam defines its own run_cmd for test compatibility.
"""

import logging
import subprocess
from typing import List, Optional

logger = logging.getLogger("shared.utils")


class ToolError(RuntimeError):
    """Raised when a forensic tool fails or is not found."""


def run_tool(
    binary: str,
    args: List[str],
    timeout: int = 3600,
    cwd: Optional[str] = None,
    ok_returncodes: tuple = (0,),
) -> str:
    """
    Run a forensic CLI tool and return its stdout.
    Raises ToolError on failure, missing binary, or timeout.
    """
    cmd = [binary] + args
    logger.debug("Exec: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        if result.returncode not in ok_returncodes:
            raise ToolError(
                f"{binary} exited {result.returncode}: {result.stderr[:400]}"
            )
        return result.stdout
    except FileNotFoundError:
        raise ToolError(f"Tool not found on PATH: {binary}")
    except subprocess.TimeoutExpired:
        raise ToolError(f"{binary} timed out after {timeout}s")
