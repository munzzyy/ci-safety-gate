import sys
from pathlib import Path

# scan_secrets.py lives at the repo root, not inside a package, since this
# repo ships an action, not an installable library.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
