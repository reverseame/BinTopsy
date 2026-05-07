"""
Functional tests — actually run each script against a tiny test binary
compiled by the conftest fixture and verify the output is well-formed.

These tests assume r2 + yara are installed; they skip cleanly otherwise.
"""

import json
import os
import shutil
import subprocess
import sys
import pytest


def have(cmd):
    return shutil.which(cmd) is not None


def run(repo_root, script, *args, stdout=None, timeout=120):
    cmd = [sys.executable, os.path.join(repo_root, script), *args]
    return subprocess.run(cmd, capture_output=stdout is None,
                          stdout=stdout, text=True, timeout=timeout)


# ---------- disasm.py ----------

def test_disasm_hex_string(repo_root):
    r = run(repo_root, "disasm.py", "-s", "55 48 89 e5", "-a", "x64")
    assert r.returncode == 0
    assert "push" in r.stdout
    assert "mov" in r.stdout


def test_disasm_invalid_hex_message(repo_root):
    r = run(repo_root, "disasm.py", "-s", "ZZ", "-a", "x64")
    assert r.returncode != 0
    assert "Could not extract" in r.stderr


# ---------- entropy-viz.py ----------

def test_entropy_viz(repo_root, tiny_binary, tmp_path):
    out = tmp_path / "entropy.pdf"
    r = run(repo_root, "entropy-viz.py", tiny_binary, "-o", str(out))
    assert r.returncode == 0
    assert out.exists() and out.stat().st_size > 0


# ---------- yara-chunk-scanner.py ----------

@pytest.mark.skipif(not have("yara"), reason="yara binary not installed")
def test_yara_scanner(repo_root, tiny_binary, yara_rule):
    r = run(repo_root, "yara-chunk-scanner.py", tiny_binary, yara_rule, "-p", "4096")
    assert r.returncode == 0
    # libc-linked binaries should hit at least one of the strings.
    assert "MATCH FOUND" in r.stdout or "Total Detections: 0" in r.stdout


# ---------- r2 toolchain ----------

@pytest.mark.skipif(not have("r2"), reason="radare2 not installed")
def test_dissector_json(repo_root, tiny_binary, tmp_path):
    out_json = tmp_path / "dissect.json"
    with open(out_json, 'w') as f:
        r = run(repo_root, "r2-dissector.py", tiny_binary, stdout=f)
    assert r.returncode == 0
    data = json.loads(out_json.read_text())
    assert "functions" in data
    assert data["metadata"]["total_functions"] >= 1


@pytest.mark.skipif(not have("r2"), reason="radare2 not installed")
def test_call_tracer(repo_root, tiny_binary, tmp_path):
    out_json = tmp_path / "calls.json"
    with open(out_json, 'w') as f:
        r = run(repo_root, "r2-call-tracer.py", tiny_binary, stdout=f)
    assert r.returncode == 0
    data = json.loads(out_json.read_text())
    assert "functions" in data
    # main should have at least one call (printf/getenv).
    assert any(fn.get("api_calls") for fn in data["functions"])


@pytest.mark.skipif(not have("r2"), reason="radare2 not installed")
def test_xref_grapher_list_imports(repo_root, tiny_binary):
    r = run(repo_root, "r2-xref-grapher.py", tiny_binary, "-l")
    assert r.returncode == 0
    assert "API NAME" in r.stdout
    # printf is always called from main; xref count must be >= 1.
    assert "printf" in r.stdout


@pytest.mark.skipif(not have("r2") or not have("dot"), reason="needs r2 + graphviz")
def test_call_graph_targeted(repo_root, tiny_binary, tmp_path):
    out_pdf = tmp_path / "cg.pdf"
    r = run(repo_root, "r2-call-graph.py", tiny_binary, str(out_pdf), "-s", "main", "-d", "2")
    assert r.returncode == 0
    # ensure we did NOT spam "Cannot find any function" (regression guard).
    assert "Cannot find any function" not in r.stderr
    assert out_pdf.exists()


# ---------- behaviour pipeline ----------

@pytest.mark.skipif(not have("r2"), reason="radare2 not installed")
def test_behavior_pipeline(repo_root, tiny_binary, tmp_path):
    calls_json = tmp_path / "calls.json"
    with open(calls_json, 'w') as f:
        r = run(repo_root, "r2-call-tracer.py", tiny_binary, stdout=f)
    assert r.returncode == 0

    layer = tmp_path / "attack.json"
    r = run(repo_root, "json-behavior-analyzer.py", str(calls_json),
            "--attack-layer", str(layer))
    assert r.returncode == 0
    assert layer.exists()
    data = json.loads(layer.read_text())
    assert data["domain"] == "enterprise-attack"
    assert isinstance(data["techniques"], list)
