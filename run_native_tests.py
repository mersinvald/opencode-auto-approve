"""Run native OpenCode fixtures in isolated profiles. No model endpoint is used."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
for name in ['test_profile_native.py', 'test_grant_native.py', 'test_native_reads.py', 'test_static_native.py',
             'test_notifications_native.py']:
    print(f'Running {name}', flush=True)
    subprocess.run([sys.executable, str(root/name)], cwd=root, check=True, timeout=240)
