from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import zipfile
from pathlib import Path

import pytest


@pytest.mark.slow
def test_wheel_install_finds_packaged_reference_corpus(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    dist_dir = tmp_path / "dist"

    # Given: a freshly built wheel from this checkout.
    build_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(dist_dir),
        ],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert build_result.returncode == 0, build_result.stderr

    wheels = sorted(dist_dir.glob("bugbounty_ctf-*.whl"))
    assert len(wheels) == 1
    wheel_path = wheels[0]

    # When: the wheel is inspected and extracted as the only importable project path.
    with zipfile.ZipFile(wheel_path) as wheel:
        entries = wheel.namelist()
        reference_entries = [
            entry
            for entry in entries
            if entry.startswith("bugbounty_ctf/references/") and entry.endswith(".md")
        ]
        assert "bugbounty_ctf/references/nginx-ui-login-encryption.md" in reference_entries
        assert not any(entry.startswith("references/") for entry in entries)
        extract_dir = tmp_path / "wheel-root"
        wheel.extractall(extract_dir)

    isolated_cwd = tmp_path / "isolated"
    isolated_cwd.mkdir()
    smoke = textwrap.dedent(
        f"""
        import json
        from pathlib import Path

        import bugbounty_ctf.knowledge as knowledge
        from bugbounty_ctf.knowledge import KnowledgeBase

        kb = KnowledgeBase(db_path={str(tmp_path / "kb.db")!r})
        try:
            count = kb.reindex()
            results = kb.search("nginx-ui login encryption", limit=5)
            print(json.dumps({{
                "count": count,
                "filenames": [result["filename"] for result in results],
                "module_file": knowledge.__file__,
                "references_dir": kb.references_dir,
                "references_exists": Path(kb.references_dir).is_dir(),
            }}, sort_keys=True))
        finally:
            kb.close()
        """
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(extract_dir)
    run_result = subprocess.run(
        [sys.executable, "-c", smoke],
        cwd=isolated_cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert run_result.returncode == 0, run_result.stderr

    # Then: the installed package discovers and searches the shipped Markdown corpus.
    evidence = json.loads(run_result.stdout)
    assert Path(evidence["module_file"]).is_relative_to(extract_dir)
    assert evidence["references_exists"] is True
    assert evidence["count"] > 0
    assert "nginx-ui-login-encryption.md" in evidence["filenames"]
