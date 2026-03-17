"""pytest configuration — add project root to sys.path."""
import sys
from pathlib import Path

# Ensure the project root (parent of tests/) is on sys.path so that
# `import redteam.pentest_lab` and `from blueteam...` both resolve correctly
# regardless of how pytest is invoked.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
