"""
Smoke tests — every script must at least parse its arguments and print
--help without crashing. Catches missing imports, syntax errors and broken
argument definitions.
"""

import os
import subprocess
import sys
import pytest


SCRIPTS = [
    "disasm.py",
    "entropy-viz.py",
    "yara-chunk-scanner.py",
    "vt-folder-scan.py",
    "r2-dissector.py",
    "r2-call-tracer.py",
    "r2-call-graph.py",
    "r2-xref-grapher.py",
    "json-behavior-analyzer.py",
    "sda-hashes.py",
    "bintopsy-cluster.py",
    "bintopsy-diff.py",
    "bintopsy-report.py",
]


@pytest.mark.parametrize("script", SCRIPTS)
def test_help(repo_root, script):
    path = os.path.join(repo_root, script)
    result = subprocess.run(
        [sys.executable, path, "--help"],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, (
        f"{script} --help failed (rc={result.returncode})\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert "usage:" in result.stdout.lower(), (
        f"{script} --help did not print usage information"
    )
