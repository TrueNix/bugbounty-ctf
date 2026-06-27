"""Tests for pwn and forensics modules."""

from __future__ import annotations

from bugbounty_ctf.forensics import ForensicFinding, ForensicsToolkit
from bugbounty_ctf.pwn import BinaryProtections, ExploitResult, PwnToolkit


class TestBinaryProtections:
    def test_to_dict(self) -> None:
        p = BinaryProtections(arch="amd64", nx=True, pie=False, canary=True)
        d = p.to_dict()
        assert d["arch"] == "amd64"
        assert d["nx"] is True
        assert d["pie"] is False
        assert d["canary"] is True


class TestExploitResult:
    def test_to_dict(self) -> None:
        r = ExploitResult(success=True, offset=64, flag="HTB{test}", method="rop")
        d = r.to_dict()
        assert d["success"] is True
        assert d["offset"] == 64
        assert d["flag"] == "HTB{test}"


class TestPwnToolkit:
    def test_init_without_binary(self) -> None:
        pt = PwnToolkit()
        assert pt.binary_path is None
        assert pt.arch == "amd64"

    def test_init_with_nonexistent_binary(self) -> None:
        pt = PwnToolkit("/nonexistent/binary")
        assert pt.binary_path == "/nonexistent/binary"

    def test_checksec_without_binary(self) -> None:
        pt = PwnToolkit()
        protections = pt.checksec()
        assert protections.arch == "unknown"


class TestForensicFinding:
    def test_to_dict(self) -> None:
        f = ForensicFinding(tool="strings", finding_type="flag", value="HTB{test}", is_flag=True)
        d = f.to_dict()
        assert d["tool"] == "strings"
        assert d["is_flag"] is True


class TestForensicsToolkit:
    def test_init(self) -> None:
        ft = ForensicsToolkit()
        assert ft.findings == []

    def test_analyze_nonexistent_file(self) -> None:
        ft = ForensicsToolkit()
        results = ft.analyze_all("/nonexistent/file.bin")
        assert len(results) == 0

    def test_get_flags_empty(self) -> None:
        ft = ForensicsToolkit()
        assert ft.get_flags() == []

    def test_get_results_empty(self) -> None:
        ft = ForensicsToolkit()
        assert ft.get_results() == []
