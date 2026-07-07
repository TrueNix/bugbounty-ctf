from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from bugbounty_ctf import reverse
from bugbounty_ctf.reverse import ReverseToolkit, _extract_flags, _validate_symbol

RunResult = tuple[str, str, int]
CommandOutputs = Mapping[tuple[str, ...], RunResult]


@pytest.fixture
def binary(tmp_path: Path) -> str:
    path = tmp_path / "challenge"
    path.write_bytes(b"\x7fELF")
    return str(path)


def install_run_cmd_stub(
    monkeypatch: pytest.MonkeyPatch,
    command_outputs: CommandOutputs,
    *,
    default: RunResult = ("", "", -1),
) -> list[tuple[str, ...]]:
    calls: list[tuple[str, ...]] = []

    def fake_run_cmd(cmd: list[str], timeout: int = 30) -> RunResult:
        calls.append(tuple(cmd))
        return command_outputs.get(tuple(cmd), default)

    monkeypatch.setattr(reverse, "_run_cmd", fake_run_cmd)
    return calls


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("noise HTB{one} flag{two} repeated HTB{one}", {"HTB{one}", "flag{two}"}),
        ("plain text", set()),
    ],
)
def test_extract_flags_returns_unique_matches(text: str, expected: set[str]) -> None:
    assert set(_extract_flags(text)) == expected


def test_validate_symbol_returns_safe_symbol() -> None:
    assert _validate_symbol("sym.main$plt@GLIBC_2.2.5") == "sym.main$plt@GLIBC_2.2.5"


@pytest.mark.parametrize("symbol", ["main;!id", "main $(id)", "main`id`", "main function"])
def test_validate_symbol_rejects_injection_metacharacters(symbol: str) -> None:
    with pytest.raises(ValueError, match="Unsafe symbol name"):
        _validate_symbol(symbol)


def test_file_info_parses_elf_amd64_metadata(binary: str, monkeypatch: pytest.MonkeyPatch) -> None:
    output = f"{binary}: ELF 64-bit LSB executable, x86-64, dynamically linked"
    install_run_cmd_stub(monkeypatch, {("file", binary): (output, "", 0)})
    toolkit = ReverseToolkit(binary)

    info = toolkit.file_info()

    assert info == {"format": "ELF", "arch": "amd64", "info": output}
    assert toolkit.get_results()["format"] == "ELF"
    assert toolkit.get_results()["arch"] == "amd64"


def test_file_info_handles_empty_tool_output(binary: str, monkeypatch: pytest.MonkeyPatch) -> None:
    install_run_cmd_stub(monkeypatch, {("file", binary): ("", "", -1)})

    assert ReverseToolkit(binary).file_info() == {
        "format": "unknown",
        "arch": "unknown",
        "info": "",
    }


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (
            "Full RELRO\nCanary found\nNX enabled\nPIE enabled\nFORTIFY enabled",
            {"nx": True, "pie": True, "canary": True, "relro": True, "fortify": True},
        ),
        (
            "[NOT FOUND]",
            {"nx": False, "pie": False, "canary": False, "relro": False, "fortify": False},
        ),
    ],
)
def test_checksec_parses_protections_and_missing_tool(
    binary: str,
    monkeypatch: pytest.MonkeyPatch,
    output: str,
    expected: dict[str, bool],
) -> None:
    install_run_cmd_stub(monkeypatch, {("checksec", f"--file={binary}"): (output, "", 0)})

    assert ReverseToolkit(binary).checksec() == expected


def test_strings_analysis_returns_interesting_strings_and_flags(
    binary: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = "\n".join(
        ["password=hunter2", "https://target.test/admin", "gets(", "flag{strings-win}"]
    )
    install_run_cmd_stub(monkeypatch, {("strings", "-n", "4", binary): (output, "", 0)})
    toolkit = ReverseToolkit(binary)

    interesting = toolkit.strings_analysis()

    assert {"type": "password", "value": "password=hunter2"} in interesting
    assert {"type": "url", "value": "https://target.test/admin"} in interesting
    assert {"type": "vulnerable_function", "value": "gets("} in interesting
    assert toolkit.get_results()["flags"] == ["flag{strings-win}"]


def test_strings_analysis_returns_empty_list_when_no_strings(
    binary: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_run_cmd_stub(monkeypatch, {("strings", "-n", "4", binary): ("", "", 0)})
    toolkit = ReverseToolkit(binary)

    assert toolkit.strings_analysis() == []
    assert toolkit.get_results()["flags"] == []


def test_symbol_analysis_categorizes_nm_functions_variables_and_imports(
    binary: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = "\n".join(
        [
            "0000000000001139 T main",
            "0000000000004010 D global_counter",
            "                 U puts@GLIBC_2.2.5",
        ]
    )
    install_run_cmd_stub(monkeypatch, {("nm", binary): (output, "", 0)})

    assert ReverseToolkit(binary).symbol_analysis() == {
        "functions": ["main"],
        "variables": ["global_counter"],
        "imports": ["puts@GLIBC_2.2.5"],
    }


def test_symbol_analysis_returns_empty_categories_for_stripped_binary(
    binary: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_run_cmd_stub(monkeypatch, {("nm", binary): ("", "", 1)})

    assert ReverseToolkit(binary).symbol_analysis() == {
        "functions": [],
        "variables": [],
        "imports": [],
    }


def test_radare2_analysis_collects_functions_imports_and_crypto_hits(
    binary: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_run_cmd_stub(
        monkeypatch,
        {
            ("r2", "-q", "-c", "aaa; afl", binary): (
                "0x1000 12 sym.main\n0x1010 5 sym.win\n",
                "",
                0,
            ),
            ("r2", "-q", "-c", "ii", binary): ("imp.puts\nimp.system\n", "", 0),
            ("r2", "-q", "-c", "/x 67452301; /x 0123456789ABCDEF", binary): (
                "0x2000 hit0_0 67452301\n",
                "",
                0,
            ),
        },
    )

    assert ReverseToolkit(binary).radare2_analysis() == {
        "functions": ["0x1000 12 sym.main", "0x1010 5 sym.win"],
        "imports": ["imp.puts", "imp.system"],
        "crypto_constants": "0x2000 hit0_0 67452301",
    }


def test_radare2_analysis_returns_empty_when_tool_missing(
    binary: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_run_cmd_stub(monkeypatch, {}, default=("", "[NOT FOUND]", -1))

    assert ReverseToolkit(binary).radare2_analysis() == {}


def test_decompile_function_returns_radare2_output(
    binary: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = "int main(void) { return 0; }\n"
    install_run_cmd_stub(
        monkeypatch, {("r2", "-q", "-c", "aaa; s sym.main; pdc", binary): (output, "", 0)}
    )
    toolkit = ReverseToolkit(binary)

    assert toolkit.decompile_function("main") == output
    assert toolkit.get_results()["findings"][0]["details"] == {"function": "main"}


def test_decompile_function_returns_empty_when_tools_missing(
    binary: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    install_run_cmd_stub(monkeypatch, {}, default=("", "[NOT FOUND]", -1))

    assert ReverseToolkit(binary).decompile_function("main") == ""


def test_decompile_function_validates_symbol_before_running_tool(
    binary: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = install_run_cmd_stub(monkeypatch, {})

    with pytest.raises(ValueError, match="Unsafe symbol name"):
        ReverseToolkit(binary).decompile_function("main;!id")
    assert calls == []


def test_ghidra_decompile_returns_headless_output(
    binary: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ghidra_home = tmp_path / "ghidra"
    ghidra_home.mkdir()
    monkeypatch.setenv("GHIDRA_HOME", str(ghidra_home))
    output = "=== main ===\nint main(void) { return 0; }\n"
    command = (
        f"{ghidra_home}/support/analyzeHeadless",
        "/tmp/ghidra_project",
        "temp_proj",
        "-import",
        binary,
        "-postScript",
        "/tmp/ghidra_decompile.py",
        "-delete",
    )
    install_run_cmd_stub(monkeypatch, {command: (output, "", 0)})
    toolkit = ReverseToolkit(binary)

    assert toolkit.ghidra_decompile("main") == output
    assert toolkit.get_results()["findings"][0]["tool"] == "ghidra"


def test_ghidra_decompile_returns_empty_when_home_missing(
    binary: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    calls = install_run_cmd_stub(monkeypatch, {})

    assert ReverseToolkit(binary).ghidra_decompile("main") == ""
    assert calls == []


def test_find_flags_returns_unique_flags_from_strings_and_radare2(
    binary: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run_cmd(cmd: list[str], timeout: int = 30) -> RunResult:
        calls.append(tuple(cmd))
        if cmd == ["strings", binary]:
            return "noise HTB{from_strings}", "", 0
        if cmd[:3] == ["r2", "-q", "-c"] and "HTB" in cmd[3]:
            return "0x2000 HTB{from_r2}", "", 0
        return "", "", 0

    monkeypatch.setattr(reverse, "_run_cmd", fake_run_cmd)

    assert set(ReverseToolkit(binary).find_flags()) == {"HTB{from_strings}", "HTB{from_r2}"}
    assert ("strings", binary) in calls


def test_find_flags_returns_empty_when_no_patterns_match(
    binary: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_run_cmd_stub(monkeypatch, {}, default=("", "", 0))

    assert ReverseToolkit(binary).find_flags() == []


def test_disassemble_function_returns_radare2_output(
    binary: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = "pdf output for main\n"
    install_run_cmd_stub(
        monkeypatch, {("r2", "-q", "-c", "aaa; s sym.main; pdf", binary): (output, "", 0)}
    )

    assert ReverseToolkit(binary).disassemble_function("main") == output


def test_disassemble_function_falls_back_to_objdump_section(
    binary: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    objdump = "\n".join(
        ["0000000000001139 <main>:", "  1139:\t55\tpush %rbp", "  113a:\tc3\tret", ""]
    )
    install_run_cmd_stub(
        monkeypatch,
        {
            ("r2", "-q", "-c", "aaa; s sym.main; pdf", binary): ("", "", -1),
            ("objdump", "-d", binary): (objdump, "", 0),
        },
    )

    assert ReverseToolkit(binary).disassemble_function("main") == (
        "0000000000001139 <main>:\n  1139:\t55\tpush %rbp\n  113a:\tc3\tret\n"
    )


def test_disassemble_function_returns_empty_when_tools_missing(
    binary: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_run_cmd_stub(monkeypatch, {}, default=("", "[NOT FOUND]", -1))

    assert ReverseToolkit(binary).disassemble_function("main") == ""


def test_disassemble_function_validates_symbol_before_running_tool(
    binary: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = install_run_cmd_stub(monkeypatch, {})

    with pytest.raises(ValueError, match="Unsafe symbol name"):
        ReverseToolkit(binary).disassemble_function("main $(id)")
    assert calls == []


def test_analyze_runs_tools_and_returns_results_shape(
    binary: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_run_cmd_stub(
        monkeypatch,
        {
            ("file", binary): (
                f"{binary}: ELF 64-bit LSB executable, x86-64, dynamically linked",
                "",
                0,
            ),
            ("checksec", f"--file={binary}"): ("NX enabled\nPIE enabled", "", 0),
            ("strings", "-n", "4", binary): ("token=abc\nCTF{from_analyze}", "", 0),
            ("nm", binary): ("0000000000001139 T main", "", 0),
            ("r2", "-q", "-c", "aaa; afl", binary): ("0x1000 12 sym.main", "", 0),
            ("r2", "-q", "-c", "ii", binary): ("imp.puts", "", 0),
            ("r2", "-q", "-c", "/x 67452301; /x 0123456789ABCDEF", binary): ("", "", 0),
            ("strings", binary): ("CTF{from_analyze}", "", 0),
        },
        default=("", "", 0),
    )

    results = ReverseToolkit(binary).analyze()

    assert results["format"] == "ELF"
    assert results["arch"] == "amd64"
    assert "CTF{from_analyze}" in results["flags"]
    assert any(finding["tool"] == "radare2" for finding in results["findings"])


def test_analyze_returns_empty_dict_for_missing_binary(tmp_path: Path) -> None:
    assert ReverseToolkit(str(tmp_path / "missing")).analyze() == {}


def test_get_results_returns_empty_collections_before_analysis(binary: str) -> None:
    assert ReverseToolkit(binary).get_results() == {
        "findings": [],
        "flags": [],
        "arch": "unknown",
        "format": "unknown",
    }
