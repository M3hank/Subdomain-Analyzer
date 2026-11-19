"""Scoring tests: determinism, clamping, caps, and monotonic severity."""

import subdomain


SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def test_clamp_score_bounds():
    assert subdomain.clamp_score(-100) == 0
    assert subdomain.clamp_score(0) == 0
    assert subdomain.clamp_score(42) == 42
    assert subdomain.clamp_score(100) == 100
    assert subdomain.clamp_score(101) == 100
    assert subdomain.clamp_score(10_000) == 100
    assert subdomain.clamp_score("not-a-number") == 0


def test_severity_threshold_boundaries():
    expected = {
        0: "INFO",
        4: "INFO",
        5: "LOW",
        14: "LOW",
        15: "MEDIUM",
        29: "MEDIUM",
        30: "HIGH",
        49: "HIGH",
        50: "CRITICAL",
        100: "CRITICAL",
        500: "CRITICAL",
        -5: "INFO",
    }
    for score, severity in expected.items():
        assert subdomain.classify_severity(score) == severity


def test_severity_mapping_is_monotonic():
    previous = -1
    for score in range(0, 101):
        rank = SEVERITY_RANK[subdomain.classify_severity(score)]
        assert rank >= previous
        previous = rank


def test_age_score_is_monotonic():
    values = [None, 0, 1, 2, 4, 5, 9, 10, 20]
    scores = [subdomain.score_age(value) for value in values]
    assert scores == sorted(scores)
    assert scores[0] == 0
    assert scores[-1] == 10


def test_keyword_analysis_uses_tokens_not_substrings():
    points, matched = subdomain.analyze_subdomain_name("admin.example.com")
    assert points == 5
    assert matched == ["admin"]

    # "administrator" must not match "admin" by substring.
    points, matched = subdomain.analyze_subdomain_name("administrator.example.com")
    assert matched == ["administrator"]
    assert points == 5

    points, matched = subdomain.analyze_subdomain_name("api.dev.example.com")
    assert matched == ["api", "dev"]
    assert points == 10


def test_keyword_signal_is_capped_and_deterministic():
    host = (
        "admin.api.dev.test.staging.qa.mail.portal.vpn.jenkins."
        "gitlab.jira.confluence.graphql.console.example.com"
    )
    first = subdomain.keyword_signal(host)
    second = subdomain.keyword_signal(host)
    assert first == second
    assert first.points == subdomain.KEYWORD_CAP
    assert first.name == "keywords"


def test_status_code_scoring():
    assert subdomain.score_status_code(401) == 8
    assert subdomain.score_status_code(403) == 7
    assert subdomain.score_status_code(200) == 0
    assert subdomain.score_status_code(404) == 0


def test_security_header_scoring_missing_and_cors():
    all_present = {name: "present" for name in subdomain.SECURITY_HEADERS}
    points, issues = subdomain.score_security_headers(all_present)
    assert points == 0
    assert issues == []

    points, issues = subdomain.score_security_headers({})
    assert points == sum(subdomain.SECURITY_HEADERS.values())
    assert len(issues) == len(subdomain.SECURITY_HEADERS)

    permissive = dict(all_present)
    permissive["Access-Control-Allow-Origin"] = "*"
    points, issues = subdomain.score_security_headers(permissive)
    assert points == 5
    assert any("cors" in issue for issue in issues)

    credentialed = dict(all_present)
    credentialed["Access-Control-Allow-Origin"] = "https://evil.example"
    credentialed["Access-Control-Allow-Credentials"] = "true"
    points, issues = subdomain.score_security_headers(credentialed)
    assert points == 8
    assert any("credentials=true" in issue for issue in issues)


def test_url_path_scoring_and_caps():
    points, matched = subdomain.analyze_urls(
        [
            "https://x.example/.git/config",
            "https://x.example/api/v1/users",
            "https://x.example/about",
        ]
    )
    assert matched["high"] == ["/.git/config"]
    assert matched["medium"] == ["/api/v1/users"]
    assert matched["low"] == ["/about"]
    assert points == 7 + 5 + 2

    # Many matches must still be capped per tier.
    many = [f"https://x.example/admin/page{i}" for i in range(40)]
    points, matched = subdomain.analyze_urls(many)
    assert points == 50
    assert len(matched["high"]) == 40

    # URL paths are lowercased, so mixed-case risk paths must still match.
    points, matched = subdomain.analyze_urls(
        ["https://x.example/.git/HEAD", "https://x.example/adminLogin"]
    )
    assert matched["high"] == ["/.git/head", "/adminlogin"]
    assert points == 14


def test_result_score_is_clamped_and_breakdown_matches_signals():
    analyzer = subdomain.Analyzer(
        subdomain.Config(offline=True, no_cache=True, skip_wappalyzer=True)
    )
    huge = [
        subdomain.Signal("keywords", 80, "many"),
        subdomain.Signal("paths", 90, "many"),
        subdomain.Signal("technology", 25, "many"),
        subdomain.Signal("age", 10, "old"),
        subdomain.Signal("status_code", 8, "403"),
        subdomain.Signal("security_headers", 28, "missing"),
    ]
    result = analyzer._build_result("admin.example.com", huge)
    assert result["score"] == 100
    assert result["total_points"] == 100
    assert sum(result["score_breakdown"].values()) == 241
    assert result["severity"] == "CRITICAL"
    assert all(0 <= signal["points"] <= 100 for signal in result["signals"])


def test_offline_analysis_scores_hostname_only():
    analyzer = subdomain.Analyzer(
        subdomain.Config(offline=True, no_cache=True, skip_wappalyzer=True)
    )
    result = analyzer.analyze("admin.dev.example.com")
    assert result["score"] == 10
    assert result["severity"] == "LOW"
    assert result["status_code"] is None
    assert result["is_live"] is None
    assert result["age_years"] is None
    assert result["tech"] == []
    assert result["signals"] == [
        {"name": "keywords", "points": 10, "detail": "admin, dev"}
    ]
