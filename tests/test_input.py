"""Input normalisation and loading tests."""

import io
import logging

import pytest

import subdomain


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("https://Sub.Example.com:8443/path?q=1", "sub.example.com"),
        ("http://user:pass@example.com:8080/x", "example.com"),
        ("*.dev.example.com", "dev.example.com"),
        ("https://*.api.example.com", "api.example.com"),
        ("dev.example.com.", "dev.example.com"),
        ("example.com:443", "example.com"),
        ("  API.Example.COM  ", "api.example.com"),
        ("127.0.0.1", "127.0.0.1"),
        ("http://[2001:db8::1]:8080/", "2001:db8::1"),
        ("localhost", "localhost"),
        ("bücher.example.com", "xn--bcher-kva.example.com"),
        ("exa_mple.com", "exa_mple.com"),
        (None, None),
        ("", None),
        ("   ", None),
        ("# comment", None),
        ("; comment", None),
        ("// comment", None),
        ("bad host", None),
        ("example.com:abc", None),
        ("https://example.com:99999/", None),
        ("-bad.example.com", None),
        ("bad-.example.com", None),
        ("a..b.com", None),
        ("http://", None),
        ("https:///path", None),
        ("x" * 64 + ".example.com", None),
    ],
)
def test_normalize_hostname(raw, expected):
    assert subdomain.normalize_hostname(raw) == expected


def test_load_subdomains_dedupes_sorts_and_skips_comments(tmp_path, caplog):
    source = tmp_path / "subs.txt"
    source.write_text(
        "\n".join(
            [
                "# a comment",
                "",
                "https://API.example.com:443/path",
                "api.example.com",
                "*.dev.example.com",
                "bad host",
                "  ",
                "// another comment",
            ]
        ),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING, logger="subdomain-analyzer"):
        hosts = subdomain.load_subdomains(str(source))

    assert hosts == ["api.example.com", "dev.example.com"]
    assert any("invalid host" in record.getMessage().lower() for record in caplog.records)


def test_load_subdomains_reads_stdin(monkeypatch):
    monkeypatch.setattr(
        subdomain.sys,
        "stdin",
        io.StringIO("# comment\napi.example.com\nAPI.example.com\n"),
    )
    assert subdomain.load_subdomains("-") == ["api.example.com"]


def test_load_subdomains_missing_file_raises_input_error():
    with pytest.raises(subdomain.InputError):
        subdomain.load_subdomains("/nonexistent/path/subs.txt")


def test_load_subdomains_all_invalid_returns_empty(tmp_path):
    source = tmp_path / "subs.txt"
    source.write_text("# only comments\nbad host\n", encoding="utf-8")
    assert subdomain.load_subdomains(str(source)) == []
