"""CLI end-to-end tests with a monkeypatched analyzer."""

import io
import json

import pytest

import subdomain


def _write_inputs(tmp_path, lines):
    path = tmp_path / "subs.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _fake_analyze(self, host):
    return self._build_result(
        host,
        [subdomain.Signal("keywords", 20, "fake signal")],
        is_live=True,
        status_code=200,
    )


def test_cli_end_to_end_json_top_and_explain(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(subdomain.Analyzer, "analyze", _fake_analyze)
    source = _write_inputs(
        tmp_path, ["admin.example.com", "api.example.com", "www.example.com"]
    )
    output = tmp_path / "report.json"

    code = subdomain.main(
        [
            "-i", str(source),
            "-o", str(output),
            "-f", "json",
            "-t", "2",
            "--offline",
            "--no-cache",
            "--top", "2",
            "--explain",
            "-q",
        ]
    )

    assert code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["tool"] == "subdomain-analyzer"
    assert payload["total_analyzed"] == 3
    assert payload["top_n"] == 2
    assert len(payload["top"]) == 2
    assert payload["results"][0]["score"] == 20

    top_file = tmp_path / "report_top2.txt"
    assert len(top_file.read_text(encoding="utf-8").splitlines()) == 2

    stderr = capsys.readouterr().err
    assert "keywords" in stderr
    assert "TOTAL" in stderr


def test_cli_backwards_compatible_txt_command(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(subdomain.Analyzer, "analyze", _fake_analyze)
    source = _write_inputs(tmp_path, ["admin.example.com"])
    output = tmp_path / "report.txt"

    code = subdomain.main(
        [
            "-i", str(source),
            "-o", str(output),
            "-f", "txt",
            "-t", "10",
            "--offline",
            "--no-cache",
            "-q",
        ]
    )

    assert code == 0
    assert output.exists()
    assert "Score Breakdown" in output.read_text(encoding="utf-8")


def test_cli_csv_output(monkeypatch, tmp_path):
    monkeypatch.setattr(subdomain.Analyzer, "analyze", _fake_analyze)
    source = _write_inputs(tmp_path, ["admin.example.com"])
    output = tmp_path / "report.csv"

    code = subdomain.main(
        ["-i", str(source), "-o", str(output), "-f", "csv", "--offline", "--no-cache", "-q"]
    )

    assert code == 0
    lines = output.read_text(encoding="utf-8").splitlines()
    assert lines[0] == ",".join(subdomain.CSV_FIELDS)
    assert len(lines) == 2


def test_cli_no_valid_inputs_returns_2(tmp_path, capsys):
    source = _write_inputs(tmp_path, ["# comment", "bad host", ""])
    output = tmp_path / "report.json"

    code = subdomain.main(
        ["-i", str(source), "-o", str(output), "-f", "json", "-q"]
    )

    assert code == 2
    assert not output.exists()
    assert "No valid subdomains" in capsys.readouterr().err


def test_cli_missing_input_returns_1(tmp_path, capsys):
    output = tmp_path / "report.json"
    code = subdomain.main(
        ["-i", str(tmp_path / "missing.txt"), "-o", str(output), "-f", "json", "-q"]
    )
    assert code == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as excinfo:
        subdomain.main(["--version"])
    assert excinfo.value.code == 0
    assert subdomain.VERSION in capsys.readouterr().out


def test_cli_stdin_and_stdout(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(subdomain.Analyzer, "analyze", _fake_analyze)
    monkeypatch.setattr(
        subdomain.sys, "stdin", io.StringIO("admin.example.com\napi.example.com\n")
    )

    code = subdomain.main(
        ["-i", "-", "-o", "-", "-f", "json", "--offline", "--no-cache", "-q"]
    )

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total_analyzed"] == 2


def test_cli_offline_end_to_end_makes_no_network_calls(monkeypatch, tmp_path):
    def boom(*_args, **_kwargs):
        raise AssertionError("offline CLI must not touch the network")

    monkeypatch.setattr(subdomain.NetworkClient, "get", boom)
    monkeypatch.setattr(subdomain.subprocess, "run", boom)
    monkeypatch.setattr(subdomain.shutil, "which", boom)

    source = _write_inputs(
        tmp_path, ["https://Admin.Example.com:443/x", "api.example.com"]
    )
    output = tmp_path / "offline.json"

    code = subdomain.main(
        ["-i", str(source), "-o", str(output), "-f", "json", "--offline", "-q"]
    )

    assert code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["total_analyzed"] == 2
    assert all(result["status_code"] is None for result in payload["results"])
    assert all(result["severity"] != "DEAD" for result in payload["results"])
