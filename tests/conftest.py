from __future__ import annotations

import sys
from pathlib import Path


PROJECT_PARENT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_PARENT))
