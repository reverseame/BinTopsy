"""
Shared pytest fixtures.

The `tiny_binary` fixture compiles a minimal C program once per session so
end-to-end tests have something real to disassemble. If no C compiler is
available, the affected tests are skipped — they don't fail.
"""

import os
import shutil
import subprocess
import textwrap
import pytest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="session")
def repo_root():
    return REPO_ROOT


@pytest.fixture(scope="session")
def tiny_binary(tmp_path_factory):
    """Compile a tiny C program. Skip the test session if no compiler exists."""
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        pytest.skip("no C compiler in PATH; cannot build the test binary")

    src = textwrap.dedent("""
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>

        int triple(int x) { return x + x + x; }

        int main(int argc, char **argv) {
            const char *who = getenv("USER");
            if (!who) who = "world";
            for (int i = 0; i < argc; i++) {
                printf("hello %s, arg[%d] = %s, triple = %d\\n",
                       who, i, argv[i], triple(i));
            }
            return 0;
        }
    """)
    workdir = tmp_path_factory.mktemp("bintopsy")
    src_path = workdir / "tiny.c"
    bin_path = workdir / "tiny"
    src_path.write_text(src)

    rc = subprocess.call([cc, str(src_path), "-O0", "-o", str(bin_path)])
    if rc != 0:
        pytest.skip(f"failed to compile test binary (rc={rc})")
    return str(bin_path)


@pytest.fixture(scope="session")
def yara_rule(tmp_path_factory):
    """A YARA rule that matches a string we know is in libc-linked binaries."""
    workdir = tmp_path_factory.mktemp("bintopsy_yara")
    rule_path = workdir / "test.yar"
    rule_path.write_text(
        'rule HasGlibcLikeSymbol {\n'
        '  strings:\n'
        '    $a = "printf"\n'
        '    $b = "stdio"\n'
        '  condition: any of them\n'
        '}\n'
    )
    return str(rule_path)
