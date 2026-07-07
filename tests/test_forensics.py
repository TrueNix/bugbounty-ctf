from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from bugbounty_ctf import forensics
from bugbounty_ctf.forensics import ForensicFinding, ForensicsToolkit

CommandResult = tuple[str, str, int]
CommandHandler = Callable[[list[str], int], CommandResult]


def install_run_cmd_stub(
    monkeypatch: pytest.MonkeyPatch, handler: CommandHandler
) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run_cmd(cmd: list[str], timeout: int = 30) -> CommandResult:
        calls.append(cmd)
        return handler(cmd, timeout)

    monkeypatch.setattr(forensics, "_run_cmd", fake_run_cmd)
    return calls


def missing_tool(cmd: list[str], timeout: int) -> CommandResult:
    return "", f"[NOT FOUND: {cmd[0]}]", -1


def write_artifact(tmp_path: Path, name: str) -> str:
    artifact = tmp_path / name
    artifact.write_bytes(b"tiny artifact")
    return str(artifact)


def test_extract_flags_returns_unique_supported_formats() -> None:
    text = "HTB{alpha} flag{beta} CTF{gamma} pwn{delta} flag{beta}"

    flags = forensics._extract_flags(text)

    assert set(flags) == {"HTB{alpha}", "flag{beta}", "CTF{gamma}", "pwn{delta}"}
    assert len(flags) == 4


def test_extract_flags_returns_empty_when_no_pattern_matches() -> None:
    flags = forensics._extract_flags("plain forensic output without a token")

    assert flags == []


def test_file_type_and_strings_record_findings_and_flags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "sample.png")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        match cmd[0]:
            case "file":
                return "sample.png: PNG image data\n", "", 0
            case "strings":
                return "password=hunter2\napi token=abc123\npayload flag{strings}\n", "", 0
            case _:
                return missing_tool(cmd, timeout)

    install_run_cmd_stub(monkeypatch, handler)
    toolkit = ForensicsToolkit()

    toolkit._file_type(path)
    toolkit._strings(path)

    findings = {(finding.tool, finding.finding_type, finding.value) for finding in toolkit.findings}
    assert ("file", "file_type", "sample.png: PNG image data") in findings
    assert ("strings", "credential", "password=hunter2") in findings
    assert ("strings", "credential", "token=abc123") in findings
    assert toolkit.get_flags() == ["flag{strings}"]


def test_strings_clean_output_adds_no_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "clean.bin")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        match cmd[0]:
            case "strings":
                return "ordinary words only\n", "", 0
            case _:
                return missing_tool(cmd, timeout)

    install_run_cmd_stub(monkeypatch, handler)
    toolkit = ForensicsToolkit()

    toolkit._strings(path)

    assert toolkit.findings == []
    assert toolkit.get_flags() == []


def test_binwalk_records_embedded_files_without_extracting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "firmware.bin")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        match cmd[0]:
            case "binwalk":
                if "-e" in cmd:
                    return "", "", 0
                return (
                    "DECIMAL       HEXADECIMAL     DESCRIPTION\n128           0x80            PNG image\n",
                    "",
                    0,
                )
            case _:
                return missing_tool(cmd, timeout)

    install_run_cmd_stub(monkeypatch, handler)
    monkeypatch.setattr(forensics.os.path, "exists", lambda path: False)
    toolkit = ForensicsToolkit()

    toolkit._binwalk(path)

    assert len(toolkit.findings) == 1
    finding = toolkit.findings[0]
    assert finding.tool == "binwalk"
    assert finding.finding_type == "embedded_files"
    assert "PNG image" in finding.value


def test_binwalk_empty_output_is_clean(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = write_artifact(tmp_path, "plain.bin")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        match cmd[0]:
            case "binwalk":
                return "", "", 0
            case _:
                return missing_tool(cmd, timeout)

    install_run_cmd_stub(monkeypatch, handler)
    toolkit = ForensicsToolkit()

    toolkit._binwalk(path)

    assert toolkit.findings == []


def test_exiftool_records_metadata_and_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "photo.jpg")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        match cmd[0]:
            case "exiftool":
                return "Author: analyst\nComment: HTB{metadata}\n", "", 0
            case _:
                return missing_tool(cmd, timeout)

    install_run_cmd_stub(monkeypatch, handler)
    toolkit = ForensicsToolkit()

    toolkit._exiftool(path)

    assert [finding.finding_type for finding in toolkit.findings] == [
        "metadata",
        "flag_in_metadata",
    ]
    assert toolkit.get_flags() == ["HTB{metadata}"]


def test_exiftool_empty_output_is_clean(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = write_artifact(tmp_path, "empty.jpg")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        match cmd[0]:
            case "exiftool":
                return "", "", 0
            case _:
                return missing_tool(cmd, timeout)

    install_run_cmd_stub(monkeypatch, handler)
    toolkit = ForensicsToolkit()

    toolkit._exiftool(path)

    assert toolkit.findings == []


def test_analyze_pcap_records_network_artifacts_and_flags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "capture.pcap")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        if cmd == ["tshark", "-r", path, "-T", "text"]:
            return "packet payload contains flag{pcap}\n", "", 0
        if "http.request" in cmd:
            return "GET\texample.test\t/login\n", "", 0
        if "http.authorization" in cmd:
            return "Basic YWRtaW46cGFzcw==\n", "", 0
        if "ftp.request.command == USER or ftp.request.command == PASS" in cmd:
            return "USER\tadmin\nPASS\thunter2\n", "", 0
        if "dns.qry.name" in cmd:
            return "example.test\nexample.test\ncdn.example.test\n", "", 0
        return missing_tool(cmd, timeout)

    install_run_cmd_stub(monkeypatch, handler)
    toolkit = ForensicsToolkit()

    toolkit.analyze_pcap(path)

    finding_types = {finding.finding_type for finding in toolkit.findings}
    assert {
        "http_requests",
        "http_credentials",
        "ftp_credentials",
        "dns_queries",
        "flag_in_pcap",
    } <= finding_types
    assert toolkit.get_flags() == ["flag{pcap}"]


def test_analyze_pcap_missing_tools_is_clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "empty.pcap")
    install_run_cmd_stub(monkeypatch, missing_tool)
    toolkit = ForensicsToolkit()

    toolkit.analyze_pcap(path)

    assert toolkit.findings == []


def test_analyze_image_records_stego_findings_and_flags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "secret.png")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        match cmd[0]:
            case "zsteg":
                return "b1,rgb,lsb,yx .. text: HTB{zsteg}\n", "", 0
            case "steghide":
                password = cmd[cmd.index("-p") + 1]
                if password == "":
                    return "", "wrote extracted data to secret.txt\n", 0
                return "", "could not extract any data\n", 1
            case "stegseek":
                return "Found password: secret\n", "", 0
            case _:
                return missing_tool(cmd, timeout)

    install_run_cmd_stub(monkeypatch, handler)
    toolkit = ForensicsToolkit()

    toolkit.analyze_image(path)

    finding_types = {finding.finding_type for finding in toolkit.findings}
    assert {"stego_zsteg", "flag_in_stego", "stego_steghide", "stego_bruteforce"} <= finding_types
    assert toolkit.get_flags() == ["HTB{zsteg}"]


def test_analyze_image_without_hidden_data_is_clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "plain.png")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        match cmd[0]:
            case "zsteg" | "steghide" | "stegseek":
                return "", "", 1
            case _:
                return missing_tool(cmd, timeout)

    install_run_cmd_stub(monkeypatch, handler)
    toolkit = ForensicsToolkit()

    toolkit.analyze_image(path)

    assert toolkit.findings == []


def test_analyze_memory_records_volatility_fallback_hashes_and_flags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "memory.raw")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        if cmd[0] == "volatility3" and "linux.pslist.PsList" in cmd:
            return "", "[NOT FOUND: volatility3]", -1
        if cmd[0] == "vol.py":
            return "PID Name\n4 System\n1337 notepad.exe\n", "", 0
        if cmd[0] == "volatility3" and "windows.hashdump.HashDump" in cmd:
            return "Administrator:500:LMHASH:NTHASH:::\n", "", 0
        if cmd[0] == "strings":
            return "heap bytes CTF{memory}\n", "", 0
        return missing_tool(cmd, timeout)

    install_run_cmd_stub(monkeypatch, handler)
    toolkit = ForensicsToolkit()

    toolkit.analyze_memory(path)

    finding_types = {finding.finding_type for finding in toolkit.findings}
    assert {"processes", "password_hashes", "flag_in_memory"} <= finding_types
    assert toolkit.get_flags() == ["CTF{memory}"]


def test_analyze_memory_unavailable_tools_is_clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "unavailable.raw")
    install_run_cmd_stub(monkeypatch, missing_tool)
    toolkit = ForensicsToolkit()

    toolkit.analyze_memory(path)

    assert toolkit.findings == []


def test_analyze_disk_records_partitions_and_interesting_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "disk.img")
    flag_file = tmp_path / "flag.txt"
    flag_file.write_text("backup flag{disk}\n", encoding="utf-8")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        match cmd[0]:
            case "fdisk":
                return "Disk image.img: 10 MiB\nDevice Boot Start End Sectors Size Id Type\n", "", 0
            case "mount" | "umount":
                return "", "", 0
            case _:
                return missing_tool(cmd, timeout)

    install_run_cmd_stub(monkeypatch, handler)
    monkeypatch.setattr(forensics.os, "makedirs", lambda path, exist_ok=False: None)
    monkeypatch.setattr(forensics.os.path, "ismount", lambda path: True)
    monkeypatch.setattr(forensics.os, "walk", lambda path: [(str(tmp_path), [], ["flag.txt"])])
    toolkit = ForensicsToolkit()

    toolkit.analyze_disk(path)

    finding_types = {finding.finding_type for finding in toolkit.findings}
    assert {"partitions", "interesting_file"} <= finding_types
    assert toolkit.get_flags() == ["flag{disk}"]
    interesting = next(
        finding for finding in toolkit.findings if finding.finding_type == "interesting_file"
    )
    assert interesting.is_flag is True
    assert interesting.details == {"flags": ["flag{disk}"]}


def test_analyze_disk_empty_and_unmounted_is_clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "empty.img")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        match cmd[0]:
            case "fdisk" | "mount":
                return "", "", 0
            case _:
                return missing_tool(cmd, timeout)

    install_run_cmd_stub(monkeypatch, handler)
    monkeypatch.setattr(forensics.os, "makedirs", lambda path, exist_ok=False: None)
    monkeypatch.setattr(forensics.os.path, "ismount", lambda path: False)
    toolkit = ForensicsToolkit()

    toolkit.analyze_disk(path)

    assert toolkit.findings == []


def test_analyze_all_runs_common_parsers_then_pcap_dispatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "capture.pcap")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        match cmd[0]:
            case "file":
                return "capture.pcap: pcap capture file\n", "", 0
            case "strings":
                return "flag{strings_first}\n", "", 0
            case "binwalk" | "exiftool":
                return "", "", 0
            case "tshark":
                if cmd == ["tshark", "-r", path, "-T", "text"]:
                    return "packet payload HTB{wire}\n", "", 0
                return "", "", 0
            case _:
                return missing_tool(cmd, timeout)

    calls = install_run_cmd_stub(monkeypatch, handler)
    toolkit = ForensicsToolkit()

    findings = toolkit.analyze_all(path)

    assert [cmd[0] for cmd in calls[:4]] == ["file", "strings", "binwalk", "exiftool"]
    assert "tshark" in {cmd[0] for cmd in calls}
    assert findings == toolkit.findings
    assert set(toolkit.get_flags()) == {"flag{strings_first}", "HTB{wire}"}


def test_analyze_all_runs_strings_before_image_stego_dispatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = write_artifact(tmp_path, "image.png")

    def handler(cmd: list[str], timeout: int) -> CommandResult:
        match cmd[0]:
            case "file":
                return "image.png: PNG image data\n", "", 0
            case "strings":
                return "embedded flag{fast_path}\n", "", 0
            case "binwalk" | "exiftool":
                return "", "", 0
            case "zsteg" | "steghide" | "stegseek":
                return "", "", 1
            case _:
                return missing_tool(cmd, timeout)

    calls = install_run_cmd_stub(monkeypatch, handler)
    toolkit = ForensicsToolkit()

    toolkit.analyze_all(path)

    assert [cmd[0] for cmd in calls[:5]] == ["file", "strings", "binwalk", "exiftool", "zsteg"]
    assert toolkit.get_flags() == ["flag{fast_path}"]


def test_get_flags_dedupes_and_get_results_returns_dict_shape() -> None:
    toolkit = ForensicsToolkit()
    toolkit.findings = [
        ForensicFinding(tool="strings", finding_type="flag", value="HTB{dup}", is_flag=True),
        ForensicFinding(tool="tshark", finding_type="flag_in_pcap", value="HTB{dup}", is_flag=True),
        ForensicFinding(tool="exiftool", finding_type="metadata", value="camera=demo"),
    ]

    flags = toolkit.get_flags()
    results = toolkit.get_results()

    assert flags == ["HTB{dup}"]
    assert results == [
        {
            "tool": "strings",
            "finding_type": "flag",
            "value": "HTB{dup}",
            "is_flag": True,
            "details": {},
        },
        {
            "tool": "tshark",
            "finding_type": "flag_in_pcap",
            "value": "HTB{dup}",
            "is_flag": True,
            "details": {},
        },
        {
            "tool": "exiftool",
            "finding_type": "metadata",
            "value": "camera=demo",
            "is_flag": False,
            "details": {},
        },
    ]
