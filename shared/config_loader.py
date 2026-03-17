"""
Shared YAML configuration loader with graceful fallback.
"""

import logging
from typing import Any, Dict

logger = logging.getLogger("shared.config")


def load_yaml(path: str) -> Dict[str, Any]:
    """Load a YAML file; return {} on any error."""
    try:
        import yaml
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    except ImportError:
        logger.warning("PyYAML not installed — using empty config (pip3 install PyYAML)")
    except FileNotFoundError:
        logger.warning("Config file not found: %s", path)
    except Exception as exc:
        logger.warning("Config load error (%s): %s", path, exc)
    return {}
