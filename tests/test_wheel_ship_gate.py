"""Wheel-ship-gate for enshroud v1.0 RELEASE.

These tests pin the installable-and-runnable contract for the v1.0.0 release.
They run on the `ship_gate` marker; the fast CI loop is `pytest -m "not ship_gate"`.

R-003 / R-007 / AC-1..AC-13 below depend on this module.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_VERSION = "1.0.0"
EXPECTED_RELEASE_DATE = "2026-06-22"
EXPECTED_ALL_CHECKS = 34
EXPECTED_OPT_IN = 7


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=180, **kw)


@pytest.mark.ship_gate
def test_wheel_builds_cleanly(tmp_path):
    """R-003(a): `pip wheel . --no-deps` exits 0 and emits the v1.0.0 wheel."""
    out = tmp_path / "wheels"
    r = _run([sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "-w", str(out)],
             cwd=str(REPO_ROOT))
    assert r.returncode == 0, f"pip wheel FAILED:\n{r.stderr}"
    wheels = list(out.glob(f"enshroud-{EXPECTED_VERSION}-py3-none-any.whl"))
    assert wheels, f"no enshroud-{EXPECTED_VERSION} wheel found in {out}"


@pytest.mark.ship_gate
def test_wheel_installs_and_version(tmp_path):
    """R-003(b) + AC-7: wheel installs into fresh venv; CLI prints help; __version__ == 1.0.0."""
    wheel = next((tmp_path / "wheels").glob(f"enshroud-{EXPECTED_VERSION}-py3-none-any.whl"), None)
    if wheel is None:
        # Build the wheel first if the previous test didn't already.
        out = tmp_path / "wheels"
        _run([sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "-w", str(out)],
             cwd=str(REPO_ROOT))
        wheel = next(out.glob(f"enshroud-{EXPECTED_VERSION}-py3-none-any.whl"))
    venv = tmp_path / "v"
    _run([sys.executable, "-m", "venv", str(venv)])
    r = _run([str(venv / "bin" / "pip"), "install", str(wheel), "--quiet"])
    assert r.returncode == 0, f"wheel install FAILED:\n{r.stderr}"
    r = _run([str(venv / "bin" / "python"), "-c",
              "import enshroud; print(enshroud.__version__)"])
    assert r.stdout.strip() == EXPECTED_VERSION, \
        f"__version__ mismatch: got {r.stdout.strip()!r}, want {EXPECTED_VERSION!r}"
    r = _run([str(venv / "bin" / "enshroud"), "--help"])
    assert r.returncode == 0, f"enshroud --help FAILED:\n{r.stderr}"
    assert "GraphQL" in r.stdout or "graphql" in r.stdout.lower(), \
        f"enshroud --help missing GraphQL in description:\n{r.stdout[:200]}"


@pytest.mark.ship_gate
def test_wheel_imports_all_modules(tmp_path):
    """R-003(c): every src/enshroud/ subpackage + every check module imports cleanly from the wheel-install."""
    venv = tmp_path / "v"
    _run([sys.executable, "-m", "venv", str(venv)])
    out = tmp_path / "wheels"
    _run([sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "-w", str(out)],
         cwd=str(REPO_ROOT))
    wheel = next(out.glob(f"enshroud-{EXPECTED_VERSION}-py3-none-any.whl"))
    _run([str(venv / "bin" / "pip"), "install", str(wheel), "--quiet"])
    # Probe the wheel directly via zipfile: extract the check module list and try importing each.
    with zipfile.ZipFile(wheel) as z:
        check_names = sorted(
            n.split("/")[2].split(".")[0]
            for n in z.namelist()
            if n.startswith("enshroud/checks/") and n.endswith(".py")
            and not n.endswith("__init__.py")
        )
    assert len(check_names) >= EXPECTED_ALL_CHECKS + EXPECTED_OPT_IN, \
        f"expected >= {EXPECTED_ALL_CHECKS + EXPECTED_OPT_IN} checks in wheel, found {len(check_names)}: {check_names}"
    code = (
        "import importlib, sys, pkgutil\n"
        "import enshroud, enshroud.checks\n"
        "mod_names = [m.name for m in pkgutil.iter_modules(enshroud.checks.__path__)]\n"
        "for n in mod_names:\n"
        "    importlib.import_module(f'enshroud.checks.{n}')\n"
        "print(f'OK {len(mod_names)} check modules imported')\n"
    )
    r = _run([str(venv / "bin" / "python"), "-c", code])
    assert r.returncode == 0, f"import FAILED:\n{r.stderr}"
    assert "OK" in r.stdout and "check modules imported" in r.stdout


@pytest.mark.ship_gate
def test_editable_install_pth_points_to_existing_src(tmp_path):
    """R-003(d) + AC-10: editable-install resolves to <REPO>/src/enshroud/, NOT a stale worktree path.

    Closes the regression class surfaced in issues.md 2026-06-18T18:04:39Z where the local
    .venv/ had a stale .pth pointing at a deleted worktree.
    """
    venv = tmp_path / "v"
    _run([sys.executable, "-m", "venv", str(venv)])
    r = _run([str(venv / "bin" / "pip"), "install", "-e", ".[dev]", "--quiet"],
             cwd=str(REPO_ROOT))
    assert r.returncode == 0, f"editable install FAILED:\n{r.stderr}"
    r = _run([str(venv / "bin" / "python"), "-c",
              "import enshroud; p = __import__('pathlib').Path(enshroud.__file__).resolve(); "
              "print(str(p.parent.parent))"])
    assert r.returncode == 0, f"__file__ probe FAILED:\n{r.stderr}"
    actual = Path(r.stdout.strip())
    expected = (REPO_ROOT / "src").resolve()
    assert actual == expected, \
        f"editable-install resolves to {actual!s}, expected {expected!s} — stale .pth regression!"
    # Belt-and-braces: no editable .pth files should point to deleted worktrees.
    site = next((venv / "lib").glob("python*/site-packages"), None)
    if site is not None:
        for pth in site.glob("__editable__.enshroud*.pth"):
            target = Path(pth.read_text().strip()).resolve()
            assert target.exists(), \
                f"stale editable .pth at {pth} points to non-existent {target}"


@pytest.mark.ship_gate
def test_changelog_exists_with_v1_0_0_entry():
    """R-003(e) + R-007 + AC-8 + AC-9: CHANGELOG.md exists with ## [1.0.0] + 2026-06-22."""
    cl = REPO_ROOT / "CHANGELOG.md"
    assert cl.exists(), f"CHANGELOG.md missing at {cl}"
    text = cl.read_text()
    assert re.search(r"^## \[1\.0\.0\]", text, re.M), \
        f"CHANGELOG.md missing '## [1.0.0]' heading:\n{text[:500]}"
    assert EXPECTED_RELEASE_DATE in text, \
        f"CHANGELOG.md missing release date {EXPECTED_RELEASE_DATE}:\n{text[:500]}"
    # Verify all 36 PRs are referenced (no PR dropped — the rejection cause for -001).
    for pr_num in range(1, 37):
        assert f"(#{pr_num})" in text, f"CHANGELOG.md missing reference to PR #{pr_num}"
