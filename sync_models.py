from dataclasses import dataclass
from pathlib import Path


@dataclass
class SyncPair:
    source: Path
    target: Path
