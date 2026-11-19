"""Report writer tests: JSON schema, CSV headers, TXT breakdown, top-N."""

import csv
import json

import subdomain


def _offline_analyzer():
    return subdomain.Analyzer(
        subdomain.Config(offline=True, no_cache=True, quiet=True)
    )


def _live_results():
    analyzer = _offline_analyzer()
    return [
        analyzer.analyze("admin.example.com"),
        analyzer.analyze("api.example.com"),
        analyzer.analyze("www.example.com"),
    ]


def _dead_result(analyzer, host="dead.example.com"):
    return analyzer._build_result(
        host,
        [subdomain.Signal("liveness", 0, "no HTTP response")],
        severity="DEAD",
        is_live=False,
        status_code=0,
    )


def test_json_report_schema_and_values(tmp_path):
    results = _live_results()
    path = tmp_path / "report.json"
    subdomain.write_json_report(results, str(path), top_n=2)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["tool"] == "subdomain-analyzer"
    assert payload["version"] == subdomain.VERSION
    assert payload["schema_version"] == 2
    assert payload["generated_at"].endswith("Z")
    assert payload["total_analyzed"] == len(results)
    assert payload["top_n"] == 2
    assert payload["top"] == ["admin.example.com", "api.example.com"]

    for result in payload["results"]:
        assert set(
            ["subdomain", "score", "severity", "signals", "status_code", "tech", "age_years"]
        ).issubset(result)
        assert 0 <= result["score"] <= 100
        assert isinstance(result["signals"], list)
        for signal in result["signals"]:
            assert set(signal) == {"name", "points", "detail"}
            assert isinstance(signal["points"], int)
        # Backwards-compatible alias.
        assert result["total_points"] == result["score"]


def test_json_report_empty_results_still_has_top_level_object(tmp_path):
    path = tmp_path / "empty.json"
    subdomain.write_json_report([], str(path), top_n=3)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["results"] == []
    assert payload["total_analyzed"] == 0
    assert payload["top"] == []
    assert payload["top_n"] == 3


def test_json_top_excludes_dead_and_error(tmp_path):
    analyzer = _offline_analyzer()
    dead = _dead_result(analyzer)
    live = analyzer.analyze("admin.example.com")
    path = tmp_path / "report.json"
    subdomain.write_json_report([dead, live], str(path), top_n=5)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["top"] == ["admin.example.com"]


def test_csv_report_has_header_even_with_no_results(tmp_path):
    path = tmp_path / "empty.csv"
    subdomain.write_csv_report([], str(path))
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert lines[0] == ",".join(subdomain.CSV_FIELDS)


def test_csv_report_rows(tmp_path):
    analyzer = _offline_analyzer()
    results = [analyzer.analyze("admin.example.com"), _dead_result(analyzer)]
    path = tmp_path / "report.csv"
    subdomain.write_csv_report(results, str(path))

    with open(path, encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert rows[0]["subdomain"] == "admin.example.com"
    assert rows[0]["score"] == "5"
    assert "keywords=5" in rows[0]["signals"]
    assert rows[1]["severity"] == "DEAD"


def test_txt_report_contains_explanation(tmp_path):
    results = _live_results()
    path = tmp_path / "report.txt"
    subdomain.write_txt_report(results, str(path))
    text = path.read_text(encoding="utf-8")
    assert "SUBDOMAIN ANALYSIS REPORT" in text
    assert "Score Breakdown" in text
    assert "keywords" in text
    assert "+5" in text
    assert "TOTAL" in text
    assert "SEVERITY SUMMARY" in text


def test_txt_report_empty_does_not_crash(tmp_path):
    path = tmp_path / "empty.txt"
    subdomain.write_txt_report([], str(path))
    text = path.read_text(encoding="utf-8")
    assert "Total subdomains analyzed: 0" in text


def test_format_explanation_contains_signals():
    result = _offline_analyzer().analyze("admin.dev.example.com")
    explanation = subdomain.format_explanation(result)
    assert "admin.dev.example.com" in explanation
    assert "score 10" in explanation
    assert "keywords" in explanation
    assert "+10" in explanation
    assert "TOTAL" in explanation


def test_top_n_writer_skips_dead_and_errors(tmp_path):
    analyzer = _offline_analyzer()
    results = [
        _dead_result(analyzer, "dead1.example.com"),
        analyzer.analyze("admin.example.com"),
        _dead_result(analyzer, "dead2.example.com"),
        analyzer.analyze("api.example.com"),
    ]
    path = tmp_path / "top.txt"
    subdomain.write_top_n_targets(results, str(path), 5)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines == ["admin.example.com", "api.example.com"]


def test_apply_extension():
    assert subdomain.apply_extension("report", "json") == "report.json"
    assert subdomain.apply_extension("report.txt", "json") == "report.json"
    assert subdomain.apply_extension("report.json", "json") == "report.json"
    assert subdomain.apply_extension("-", "json") == "-"
