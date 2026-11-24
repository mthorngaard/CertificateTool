import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Never touch the real user settings from tests
os.environ["CERTTOOL_CONFIG_DIR"] = tempfile.mkdtemp(prefix="certtool-test-")
