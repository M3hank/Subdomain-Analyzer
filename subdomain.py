#!/usr/bin/env python3
"""
Subdomain Analyzer & Scoring System — v2.

Scores subdomains across several attack-surface signals and produces a
prioritized report in TXT, JSON, or CSV format.

Scoring signals (documented, deterministic, total clamped to 0-100):
  keywords         High-value hostname tokens (+5 each, +3 other, cap 30)
  paths            Historical URL paths matched by risk tier (cap 90)
  technology       Fingerprinted technologies (cap 25)
  age              Estimated subdomain age (1-10 points)
  status_code      Interesting HTTP status code (0-8 points)
  security_headers Missing headers + permissive CORS (0-28 points)

Severity mapping (monotonic in the score):
  CRITICAL >= 50 | HIGH >= 30 | MEDIUM >= 15 | LOW >= 5 | INFO < 5
  DEAD / ERROR are liveness/execution states, not score tiers.

Usage:
  python3 subdomain.py -i subs.txt -o report.txt -f txt -t 10
  python3 subdomain.py -i subs.txt -o report.json -f json --explain
  python3 subdomain.py -i - -o - -f json --offline < subs.txt

Exit codes:
  0 success, 1 fatal error, 2 no valid inputs.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import tldextract

# Optional: Wappalyzer may not be installed.
try:  # pragma: no cover - depends on the environment
    from Wappalyzer import Wappalyzer, WebPage

    WAPPALYZER_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    Wappalyzer = None  # type: ignore[assignment]
    WebPage = None  # type: ignore[assignment]
    WAPPALYZER_AVAILABLE = False


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------
TOOL_NAME = "subdomain-analyzer"
VERSION = "2.0.0"
SCHEMA_VERSION = 2

LOGGER = logging.getLogger(TOOL_NAME)


# ---------------------------------------------------------------------------
# Constants — Request Configuration
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 10.0
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
REQUEST_HEADERS = {"User-Agent": USER_AGENT}
DEFAULT_RATE = 5.0
DEFAULT_CACHE_TTL = 86400
DEFAULT_GAU_TIMEOUT = 180.0
DEFAULT_CACHE_DIRNAME = "subdomain-analyzer"
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"
CRTSH_URL = "https://crt.sh/"

# Scoring caps.
KEYWORD_CAP = 30
TECH_CAP = 25
SCORE_MAX = 100

# Monotonic severity ladder. Order matters: highest threshold first.
SEVERITY_THRESHOLDS: Tuple[Tuple[str, int], ...] = (
    ("CRITICAL", 50),
    ("HIGH", 30),
    ("MEDIUM", 15),
    ("LOW", 5),
    ("INFO", 0),
)
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "DEAD", "ERROR")
SIGNAL_NAMES = (
    "keywords",
    "paths",
    "technology",
    "age",
    "status_code",
    "security_headers",
)

# tldextract with no suffix-list URLs: never touches the network.
try:
    _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except Exception:  # pragma: no cover - very old tldextract
    _TLD_EXTRACT = None


# ---------------------------------------------------------------------------
# Subdomain Keywords (deduplicated)
# ---------------------------------------------------------------------------
SUBDOMAIN_KEYWORDS = sorted(
    {
        # Administrative and Login Portals
        "admin", "administrator", "root", "backend", "cpanel", "controlpanel",
        "dashboard", "manage", "sysadmin", "console", "login", "auth", "sso",
        "oauth", "account", "user", "profile", "portal",
        # Development and Testing Environments
        "dev", "development", "test", "stage", "staging", "qa", "sandbox",
        "beta", "alpha", "preprod", "prod", "uat", "preview",
        # APIs and Services
        "api", "graphql", "rest", "soap", "services", "internal", "external",
        "app", "apps", "mobile", "ios", "android", "microservices",
        # Databases and Storage
        "db", "database", "data", "sql", "mysql", "postgres", "mongodb",
        "redis", "backup", "storage", "filestorage", "archive",
        # Email and Messaging
        "mail", "email", "webmail", "smtp", "imap", "pop3", "exchange",
        # Networking and Infrastructure
        "vpn", "proxy", "gateway", "firewall", "router", "network",
        "loadbalancer", "lb", "dns", "monitor", "status",
        # Cloud and Virtualization
        "cloud", "aws", "azure", "gcp", "vm", "virtual", "docker",
        "kubernetes", "k8s", "container", "rancher", "orchestrator",
        # CI/CD
        "ci", "cd", "build", "deploy", "jenkins", "gitlab", "github",
        "bitbucket", "circleci", "travis", "teamcity", "drone", "artifactory",
        # Business Applications
        "crm", "erp", "sharepoint", "jira", "confluence", "zendesk", "sap",
        # Finance and Payment Systems
        "payment", "billing", "invoice", "checkout", "pay", "banking",
        "transaction", "wallet", "merchant", "ecommerce",
        # HR and Employee Services
        "hr", "employee", "staff", "payroll", "jobs", "careers", "talent",
        "recruitment", "onboarding", "people", "benefits",
        # Legal and Compliance
        "legal", "compliance", "audit", "policy", "gdpr", "hipaa", "ccpa",
        # Customer Support
        "support", "helpdesk", "servicedesk", "ticket",
        # Security
        "security", "authorize", "authorization", "token", "jwt",
        "password", "passwd", "vault", "secret", "ssh", "ssl", "tls",
        "encryption",
        # Miscellaneous High-Value
        "www", "static", "assets", "cdn", "blog", "news", "shop", "store",
        "m", "secure", "private",
    }
)

# High-value keywords that score higher (attack surface indicators).
HIGH_VALUE_KEYWORDS = frozenset(
    {
        "admin", "administrator", "root", "backend", "db", "database",
        "secure", "server", "internal", "login", "auth", "sysadmin",
        "portal", "api", "dev", "test", "staging", "qa", "vpn", "mail",
        "beta", "preprod", "prod", "production", "dashboard",
        "controlpanel", "manage", "management", "oauth", "user",
        "accounts", "profile", "backup", "archive", "monitor", "status",
        "dns", "proxy", "gateway", "firewall", "jenkins", "gitlab",
        "jira", "confluence", "graphql", "console", "debug", "vault",
        "secret", "payment", "billing", "cpanel",
    }
)

# ---------------------------------------------------------------------------
# Risk Path Tiers — DEDUPLICATED, NON-OVERLAPPING
# Each path exists in exactly ONE tier. Higher tiers take priority.
# Matching is PREFIX-BASED: /admin matches /admin/users/edit
# ---------------------------------------------------------------------------
HIGH_RISK_PATHS = [
    # Administrative / Login Interfaces
    "/admin", "/administrator", "/admin_area", "/admin1", "/admin2",
    "/admin123", "/admin-login", "/adminLogin", "/admin_home",
    "/adminpanel", "/admin-console", "/adm", "/admincp", "/admin_site",
    "/admincontrol", "/memberadmin", "/users/admin", "/system_admin",
    "/adminsystem", "/secure/admin", "/secret/admin", "/superuser",
    "/root", "/backend", "/manage", "/management",
    "/staff", "/moderator", "/modcp", "/useradmin",
    "/panel", "/cpanel", "/controlpanel",
    "/login", "/user/login", "/users/login", "/login.php", "/login.html",
    "/login.asp", "/login.aspx", "/signin", "/member/login",
    "/account/login", "/accounts/login", "/customer/login",
    "/client/login", "/portal/login", "/home/login",
    "/user/signin", "/users/signin", "/staff/login",
    "/admin/login", "/admin/auth", "/admin/portal", "/admin/panel",
    "/admin/control", "/admin/index.php", "/admin/index.html",
    "/admin/login.html", "/admin/dashboard", "/admin_page",
    "/login/admin", "/cms/admin", "/admin.html", "/admin.aspx",
    "/admin.php", "/adminLogin.php", "/administrator/login.php",
    # Sensitive Configuration Files
    "/.env", "/config.php", "/config.yaml", "/config.json", "/config.ini",
    "/web.config", "/application.config", "/appsettings.json",
    "/settings.php", "/db_config", "/database.yml", "/db.cfg",
    "/config.old", "/config.bak", "/config~", "/localsettings.php",
    "/wp-config.php", "/config/database.php", "/connections.yml",
    "/config.xml", "/config.jsp", "/config.asp", "/dbconfig.php",
    "/database.ini", "/database.json", "/database.xml",
    "/settings.ini", "/settings.json", "/settings.xml",
    "/app.config", "/application.ini", "/application.json",
    "/config_backup", "/config.old.php", "/config.save.php",
    "/config_backup.php",
    # Backup / Dump Files
    "/backup.sql", "/backup.zip", "/bak.zip", "/backup.tar.gz",
    "/backup_old", "/db_backup", "/database.sql", "/dump.sql",
    "/db.sql", "/db.dump", "/website.zip", "/site_backup",
    "/backup/site", "/backup/home", "/backup/www", "/backup/admin",
    "/backup/config", "/backup/database", "/backup/public_html",
    # Version Control Exposure
    "/.git", "/.git/config", "/.git/HEAD", "/.git/index",
    "/.git/logs", "/.git/refs", "/.git/objects",
    "/.git/COMMIT_EDITMSG", "/.git/FETCH_HEAD", "/.git/ORIG_HEAD",
    "/.git/description", "/.git/info", "/.git/packed-refs",
    "/.svn", "/.svn/wc.db", "/.svn/entries",
    "/.hg", "/.bzr",
    # Debug / Testing Endpoints
    "/debug", "/debugging", "/debug-info", "/phpinfo", "/info.php",
    "/test.php", "/debug.php", "/debug.asp", "/debug/config",
    "/debug/test", "/trace", "/traces", "/devinfo", "/devpanel",
    "/server-status", "/server-info", "/debug.log", "/error.log",
    "/diagnostic",
    # Setup / Install (should never be exposed)
    "/setup", "/install", "/installer", "/installation",
    "/setup.php", "/install.php",
]

MEDIUM_RISK_PATHS = [
    # API Endpoints
    "/api", "/graphql", "/rest", "/soap", "/services", "/service",
    "/api/token", "/api/login", "/api/register", "/api/logout",
    "/api/auth", "/api/data", "/api/private", "/api/public",
    "/api/admin", "/api/users", "/api/orders", "/api/v1", "/api/v2",
    "/api/v3", "/rest/v1", "/rest-api", "/api-docs",
    "/swagger", "/swagger-ui", "/openapi", "/redoc", "/api/help",
    "/api/status", "/api/health", "/api/info", "/api/metrics",
    "/api/logs", "/api/debug", "/api/test",
    "/webhook", "/callback", "/auth/callback",
    # CMS Admin Panels
    "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
    "/wp-json", "/joomla", "/drupal", "/magento", "/typo3",
    "/prestashop", "/opencart", "/store/admin", "/shop/admin",
    "/cms/login", "/umbraco", "/silverstripe", "/contao",
    "/concrete5", "/dotnetnuke", "/ghost", "/craft",
    "/processwire", "/statamic", "/expressionengine", "/october",
    "/phpbb", "/vbulletin", "/moodle", "/liferay",
    # Authentication / Authorization
    "/auth", "/authentication", "/authorize", "/session", "/sessions",
    "/token", "/tokens", "/oauth", "/oauth2", "/access", "/jwt",
    "/sso", "/signup", "/register", "/user/signup",
    "/account/logout", "/account/register",
    "/reset-password", "/forgot-password", "/user/password/reset",
    "/user/password/forgot", "/verify", "/validate",
    "/activation", "/auth.php", "/authenticator",
    "/password_reset", "/forgotpassword", "/forgot_pwd",
    "/change_password", "/password/change", "/2fa", "/mfa",
    "/security/login", "/auth/login", "/auth/signin",
    # Monitoring / Metrics
    "/monitor", "/monitoring", "/metrics", "/stats", "/statistics",
    "/analytics", "/report", "/reports", "/uptime", "/incident",
    "/incidents", "/status-report", "/status-page",
    "/grafana", "/prometheus", "/kibana", "/elk", "/zabbix",
    "/newrelic", "/datadog", "/matomo", "/logviewer",
    "/health", "/healthcheck", "/diagnostics",
    # Common Backup Extensions
    "/index.php~", "/index.php.bak", "/index.php.old",
    "/index.php.save", "/index.php.swp", "/index.html~",
    "/index.html.bak", "/index.html.old",
    "/config.php~", "/config.php.bak", "/config.php.old",
    "/config.php.save", "/config.php.swp",
    "/settings.py", "/settings.pyc", "/settings.old", "/settings.bak",
    "/.env.old", "/.env.bak", "/.env.save",
    "/web.config.old", "/web.config.bak",
    "/database.yml~", "/database.yml.bak", "/database.yml.old",
    # Application Files
    "/plugin", "/plugins", "/addon", "/addons",
    "/module", "/modules", "/vendor", "/node_modules",
    "/composer.json", "/package.json", "/yarn.lock",
    "/gulpfile.js", "/gruntfile.js",
]

LOW_RISK_PATHS = [
    "/www", "/static", "/assets", "/cdn", "/blog", "/news", "/shop",
    "/store", "/favicon.ico", "/rss", "/feed", "/atom", "/subscribe",
    "/unsubscribe", "/newsletter", "/search", "/autocomplete",
    "/customer-support", "/support-center", "/tickets",
    "/issues", "/track", "/tracking", "/alerts", "/notification",
    "/notifications", "/about", "/contact", "/contact-us", "/contactus",
    "/about-us", "/privacy", "/terms", "/terms-of-service",
    "/legal", "/careers", "/jobs", "/events", "/press", "/faq",
    "/help", "/support", "/docs", "/documentation", "/status",
    "/pricing", "/partners", "/api-keys", "/keys", "/license",
    "/downloads", "/download", "/uploads", "/media", "/public",
    "/cache", "/home", "/main", "/default", "/index", "/welcome",
    "/core", "/include", "/includes", "/inc", "/system", "/sys",
    "/cgi-bin", "/cgi", "/scripts", "/script", "/bin", "/utils",
    "/tools", "/webmail",
    # Cloud / DevOps Config (exposed = finding, but low severity alone)
    "/.aws", "/.azure", "/.env.production", "/.env.development",
    "/.env.local", "/.dockerenv", "/docker-compose.yml",
    "/Jenkinsfile", "/jenkins", "/.circleci", "/.travis.yml",
    "/.gitlab-ci.yml", "/.DS_Store", "/.idea", "/.vscode",
    "/.project", "/.editorconfig", "/azure-pipelines.yml",
    "/bitbucket-pipelines.yml", "/appveyor.yml", "/kubernetes.yml",
    "/helm", "/charts", "/k8s", "/kubernetes", "/docker",
    "/dockerfile", "/docker-compose", "/terraform", "/ansible",
    "/puppet", "/chef", "/salt", "/cloudformation",
    "/s3", "/s3bucket", "/storage", "/bucket",
]

# Sort paths longest-first for correct prefix matching
# (e.g., /admin/login should match before /admin). Paths are lowercased
# because URL paths are normalised to lowercase before matching.
HIGH_RISK_PATHS = sorted({path.lower() for path in HIGH_RISK_PATHS}, key=len, reverse=True)
MEDIUM_RISK_PATHS = sorted(
    {path.lower() for path in MEDIUM_RISK_PATHS}, key=len, reverse=True
)
LOW_RISK_PATHS = sorted({path.lower() for path in LOW_RISK_PATHS}, key=len, reverse=True)

HIGH_RISK_REGEX = re.compile(
    r"^(?:" + "|".join(re.escape(p) for p in HIGH_RISK_PATHS) + r")(?:/|$)"
)
MEDIUM_RISK_REGEX = re.compile(
    r"^(?:" + "|".join(re.escape(p) for p in MEDIUM_RISK_PATHS) + r")(?:/|$)"
)
LOW_RISK_REGEX = re.compile(
    r"^(?:" + "|".join(re.escape(p) for p in LOW_RISK_PATHS) + r")(?:/|$)"
)

# ---------------------------------------------------------------------------
# Technology Scoring — points based on historical vulnerability density
# ---------------------------------------------------------------------------
TECHNOLOGY_POINTS = {
    # Web Servers
    "apache": 7, "nginx": 5, "iis": 8, "lighttpd": 4, "caddy": 3,
    "tomcat": 8, "jetty": 6, "weblogic": 9, "websphere": 8,
    "glassfish": 7, "jboss": 8,
    # Programming Languages
    "php": 9, "python": 4, "perl": 6, "ruby": 5, "java": 6,
    "asp.net": 8, "node.js": 7, "go": 3, "rust": 2,
    "coldfusion": 9, "lua": 4, "elixir": 3, "clojure": 2,
    # CMS
    "wordpress": 10, "joomla": 9, "drupal": 9, "magento": 10,
    "typo3": 7, "prestashop": 8, "opencart": 8, "shopify": 5,
    "wix": 4, "weebly": 4, "squarespace": 4, "ghost": 5,
    "blogger": 3, "tumblr": 3,
    # Databases
    "mysql": 8, "mariadb": 7, "postgresql": 6, "mongodb": 9,
    "redis": 7, "elasticsearch": 9, "couchdb": 7, "cassandra": 6,
    "oracle": 7, "sql server": 8, "db2": 5, "hbase": 6,
    # Application Frameworks
    "django": 6, "flask": 5, "ruby on rails": 8, "laravel": 9,
    "symfony": 8, "express": 7, "spring": 7, "struts": 9,
    "codeigniter": 7, "cakephp": 7, "zend framework": 7,
    "asp.net mvc": 8,
    # JavaScript Libraries/Frameworks
    "jquery": 5, "react": 6, "angular": 7, "vue.js": 5,
    "ember.js": 5, "backbone.js": 4, "dojo": 4, "extjs": 5,
    "bootstrap": 3, "semantic ui": 3,
    # Operating Systems
    "windows": 7, "linux": 4, "ubuntu": 4, "centos": 4,
    "red hat": 4, "debian": 4, "freebsd": 3, "openbsd": 3,
    # Containers and Orchestration
    "docker": 7, "kubernetes": 7, "openshift": 6, "mesos": 5,
    "rancher": 5, "nomad": 4,
    # Authentication and Security
    "oauth": 5, "saml": 5, "ldap": 6, "active directory": 8,
    "okta": 5, "auth0": 5, "shibboleth": 6, "keycloak": 6,
    "forgerock": 6,
    # Miscellaneous
    "ftp": 8, "sftp": 4, "telnet": 10, "ssh": 4, "rdp": 9,
    "vpn": 7, "ngrok": 6,
}

# ---------------------------------------------------------------------------
# Security Header Scoring — missing headers = higher score
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    "strict-transport-security": 5,   # Missing HSTS
    "content-security-policy": 5,     # Missing CSP
    "x-frame-options": 3,             # Clickjacking
    "x-content-type-options": 2,      # MIME sniffing
    "x-xss-protection": 1,            # Legacy but still checked
    "referrer-policy": 2,             # Info leakage
    "permissions-policy": 2,          # Feature policy
}

# Status codes that indicate interesting attack surface.
INTERESTING_STATUS_CODES = {
    401: 8,   # Auth required — potential bypass
    403: 7,   # Forbidden — potential bypass (403 bypass techniques)
    500: 6,   # Server error — potential info leak
    502: 4,   # Bad gateway — potential SSRF indicator
    503: 3,   # Service unavailable — may be rate limited or behind WAF
    405: 5,   # Method not allowed — try other HTTP methods
    301: 2,   # Redirect — potential open redirect
    302: 2,
    307: 2,
}


# =====================================================================
# Small utilities
# =====================================================================
def clamp_score(value: float) -> int:
    """Clamp a score into the documented 0-100 range."""
    try:
        number = int(round(float(value)))
    except (TypeError, ValueError):
        return 0
    return max(0, min(SCORE_MAX, number))


def classify_severity(total_points: float) -> str:
    """
    Classify a score into a severity tier.

    The ladder in ``SEVERITY_THRESHOLDS`` is ordered from highest to
    lowest, so the mapping is monotonic: a higher score can never map to
    a lower severity.
    """
    score = clamp_score(total_points)
    for name, threshold in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return name
    return "INFO"


def utc_now_iso() -> str:
    """Return an RFC3339 UTC timestamp with a trailing ``Z``."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def empty_breakdown() -> Dict[str, int]:
    """Return a zeroed score breakdown with a stable key order."""
    return {name: 0 for name in SIGNAL_NAMES}


def _truncate(values: Iterable[str], limit: int = 5) -> str:
    items = list(values)
    shown = ", ".join(items[:limit])
    return f"{shown}..." if len(items) > limit else shown


def _url_host(host: str) -> str:
    """Bracket IPv6 literals for use in URLs."""
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"
    except ValueError:
        pass
    return host


def default_cache_dir() -> Path:
    """Return the default per-user cache directory."""
    base = os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / DEFAULT_CACHE_DIRNAME
    return Path.home() / ".cache" / DEFAULT_CACHE_DIRNAME


# =====================================================================
# Rate limiting
# =====================================================================
class RateLimiter:
    """Thread-safe interval limiter.

    A single instance is shared by all outbound calls made by an
    :class:`Analyzer` (HTTP requests and the ``gau`` subprocess).
    """

    def __init__(
        self,
        calls_per_second: float = DEFAULT_RATE,
        clock=time.monotonic,
        sleep=time.sleep,
    ) -> None:
        if calls_per_second <= 0:
            raise ValueError("calls_per_second must be greater than zero")
        self._min_interval = 1.0 / float(calls_per_second)
        self._clock = clock
        self._sleep = sleep
        self._last_call: Optional[float] = None
        self._lock = threading.Lock()

    def wait(self) -> None:
        """Block until the next request is allowed."""
        with self._lock:
            now = self._clock()
            if self._last_call is not None:
                delay = self._min_interval - (now - self._last_call)
                if delay > 0:
                    self._sleep(delay)
                    now = self._clock()
            self._last_call = now


# =====================================================================
# Disk cache
# =====================================================================
class DiskCache:
    """Small JSON disk cache with per-entry TTL.

    Each key is stored in its own JSON file so multiple processes can
    share the cache without a global write lock. Entries look like::

        {"key": "...", "created_at": 1700000000.0, "value": ...}
    """

    def __init__(
        self,
        directory: Optional[str] = None,
        ttl: int = DEFAULT_CACHE_TTL,
        clock=time.time,
        enabled: bool = True,
    ) -> None:
        self.directory = Path(
            os.path.expanduser(str(directory)) if directory else str(default_cache_dir())
        )
        self.ttl = int(ttl)
        self.enabled = enabled
        self._clock = clock
        self._lock = threading.RLock()

    def _path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        return self.directory / f"{digest}.json"

    def get(self, key: str) -> Tuple[bool, object]:
        """Return ``(hit, value)``; expired entries are removed."""
        if not self.enabled:
            return False, None
        with self._lock:
            path = self._path(key)
            try:
                raw = path.read_text(encoding="utf-8")
            except (OSError, ValueError):
                return False, None
            try:
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise ValueError("cache entry is not an object")
                created = float(payload["created_at"])
                value = payload["value"]
            except (KeyError, TypeError, ValueError):
                self._unlink(path)
                return False, None

            if self.ttl > 0 and (self._clock() - created) > self.ttl:
                self._unlink(path)
                return False, None
            return True, value

    def set(self, key: str, value: object) -> None:
        """Store a JSON-serialisable value. Failures are non-fatal."""
        if not self.enabled:
            return
        payload = {"key": key, "created_at": self._clock(), "value": value}
        tmp: Optional[Path] = None
        with self._lock:
            try:
                self.directory.mkdir(parents=True, exist_ok=True)
                path = self._path(key)
                tmp = path.with_name(
                    f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
                )
                tmp.write_text(
                    json.dumps(payload, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
                os.replace(str(tmp), str(path))
            except (OSError, TypeError, ValueError) as exc:
                LOGGER.debug("cache write failed for %s: %s", key, exc)
                if tmp is not None:
                    try:
                        tmp.unlink()
                    except OSError:
                        pass

    @staticmethod
    def _unlink(path: Path) -> None:
        try:
            path.unlink()
        except OSError:
            pass


# =====================================================================
# HTTP client
# =====================================================================
class NetworkClient:
    """Rate-limited HTTP client with thread-local sessions and retries."""

    def __init__(
        self,
        timeout: float = REQUEST_TIMEOUT,
        retries: int = 2,
        rate: float = DEFAULT_RATE,
        limiter: Optional[RateLimiter] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.timeout = (min(5.0, float(timeout)), float(timeout))
        self.retries = max(0, int(retries))
        self.headers = dict(headers or REQUEST_HEADERS)
        self.limiter = limiter or RateLimiter(rate)
        self._local = threading.local()

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(self.headers)
            self._local.session = session
        return session

    def get(self, url: str, **kwargs) -> requests.Response:
        """Perform a GET through the shared limiter, retrying transient errors.

        Retries are implemented here rather than in a transport adapter so
        that every outbound attempt passes through the rate limiter.
        """
        options = dict(kwargs)
        options.setdefault("timeout", self.timeout)
        options.setdefault("headers", self.headers)
        options.setdefault("verify", True)
        options.setdefault("allow_redirects", True)

        attempts = self.retries + 1
        last_error: Optional[requests.exceptions.RequestException] = None
        for attempt in range(attempts):
            self.limiter.wait()
            try:
                response = self._session().get(url, **options)
            except requests.exceptions.RequestException as exc:
                last_error = exc
                if attempt + 1 >= attempts:
                    raise
                self._retry_delay(attempt)
                continue
            if response.status_code in RETRY_STATUSES and attempt + 1 < attempts:
                self._retry_delay(attempt)
                continue
            return response

        if last_error is not None:  # pragma: no cover - loop always returns/raises
            raise last_error
        raise RuntimeError("request failed")  # pragma: no cover

    @staticmethod
    def _retry_delay(attempt: int) -> None:
        time.sleep(min(2.0, 0.3 * (2 ** attempt)))

    def get_json(self, url: str, **kwargs):
        """GET a URL and decode its JSON body."""
        response = self.get(url, **kwargs)
        return response.json()


# =====================================================================
# Input handling
# =====================================================================
class InputError(Exception):
    """Raised when the input source cannot be read."""


_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


def normalize_hostname(raw: Optional[str]) -> Optional[str]:
    """
    Normalise one input line into a bare hostname.

    Handles schemes, userinfo, ports, paths, wildcards, trailing dots,
    IDNA labels, and IPv4/IPv6 literals. Returns ``None`` for comments,
    blanks, and invalid hosts.
    """
    if raw is None:
        return None
    text = raw.strip()
    if not text or text.startswith("#") or text.startswith(";") or text.startswith("//"):
        return None
    text = re.split(r"\s+#", text, maxsplit=1)[0].strip()
    text = text.strip().strip('"').strip("'")
    if not text:
        return None
    if "://" in text:
        parsed = urlparse(text)
        host = parsed.hostname
    else:
        parsed = urlparse("//" + text)
        host = parsed.hostname
    try:
        _ = parsed.port  # force validation of malformed ports
    except ValueError:
        return None
    if not host:
        return None

    host = host.strip().strip(".").lower()
    while host.startswith("*."):
        host = host[2:]
    host = host.lstrip(".").rstrip(".")
    if not host or len(host) > 253:
        return None

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None

    labels = host.split(".")
    if any(not _HOST_LABEL.match(label) for label in labels):
        return None
    return host


def load_subdomains(source: str) -> List[str]:
    """
    Read, normalise, and deduplicate hosts.

    ``source`` is a path or ``-`` for stdin. Comments, blank lines, and
    invalid hosts are skipped (invalid hosts log a warning).
    """
    if source == "-":
        lines = sys.stdin.read().splitlines()
    else:
        try:
            with open(source, "r", encoding="utf-8-sig", errors="replace") as handle:
                lines = handle.read().splitlines()
        except FileNotFoundError as exc:
            raise InputError(f"Input file not found: {source}") from exc
        except OSError as exc:
            raise InputError(f"Cannot read input file {source}: {exc}") from exc

    hosts = set()
    invalid = 0
    for lineno, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        host = normalize_hostname(raw)
        if host is None:
            if raw.strip() and not raw.lstrip().startswith(("#", ";", "//")):
                invalid += 1
                LOGGER.warning("Skipping invalid host on line %d: %r", lineno, raw.strip())
            continue
        hosts.add(host)

    if invalid:
        LOGGER.warning("Skipped %d invalid input line(s)", invalid)
    return sorted(hosts)


# =====================================================================
# Scoring signals
# =====================================================================
@dataclass(frozen=True)
class Signal:
    """One scoring component."""

    name: str
    points: int
    detail: str

    def as_dict(self) -> Dict[str, object]:
        return {"name": self.name, "points": int(self.points), "detail": self.detail}


def _signal(name: str, points: float, detail: str) -> Signal:
    return Signal(name=name, points=max(0, int(points)), detail=detail)


def analyze_subdomain_name(subdomain: str) -> Tuple[int, List[str]]:
    """Score hostname tokens. Returns (uncapped points, matched keywords)."""
    if _TLD_EXTRACT is not None:
        try:
            parts = _TLD_EXTRACT(subdomain)
            name_part = parts.subdomain or parts.domain or subdomain
        except Exception:  # pragma: no cover - defensive
            name_part = subdomain
    else:  # pragma: no cover - only without tldextract
        name_part = subdomain

    tokens = {token for token in re.split(r"[^a-z0-9]+", name_part.lower()) if token}
    matched = sorted(tokens.intersection(SUBDOMAIN_KEYWORDS))
    points = sum(5 if keyword in HIGH_VALUE_KEYWORDS else 3 for keyword in matched)
    return points, matched


def keyword_signal(subdomain: str) -> Signal:
    points, matched = analyze_subdomain_name(subdomain)
    capped = min(points, KEYWORD_CAP)
    detail = _truncate(matched, 10) if matched else "no keyword matches"
    return _signal("keywords", capped, detail)


def score_status_code(status_code: int) -> int:
    """Score based on HTTP status code interestingness."""
    return INTERESTING_STATUS_CODES.get(status_code, 0)


def score_security_headers(headers: Dict[str, str]) -> Tuple[int, List[str]]:
    """Score MISSING security headers and permissive CORS."""
    points = 0
    issues: List[str] = []
    lowered = {str(key).lower(): value for key, value in headers.items()}

    for header, header_points in SECURITY_HEADERS.items():
        if header not in lowered:
            points += header_points
            issues.append(header)

    origin = lowered.get("access-control-allow-origin", "")
    credentials = str(lowered.get("access-control-allow-credentials", "")).lower()
    if origin == "*":
        points += 5
        issues.append("cors: Access-Control-Allow-Origin: *")
    elif origin and credentials == "true":
        points += 8
        issues.append(f"cors: origin={origin} with credentials=true")

    return points, issues


def _normalize_path(url: str) -> str:
    """Extract and normalise the path from a URL."""
    path = re.sub(r"\?.*$", "", url)
    path = re.sub(r"http[s]?://[^/]+", "", path)
    path = path.lower().rstrip("/")
    return path if path else "/"


def analyze_urls(urls: Iterable[str]) -> Tuple[int, Dict[str, List[str]]]:
    """Match unique URL paths against the risk tiers using prefix matching."""
    high_matches = set()
    medium_matches = set()
    low_matches = set()

    unique_paths = {_normalize_path(url) for url in urls}
    for path in unique_paths:
        if HIGH_RISK_REGEX.match(path):
            high_matches.add(path)
        elif MEDIUM_RISK_REGEX.match(path):
            medium_matches.add(path)
        elif LOW_RISK_REGEX.match(path):
            low_matches.add(path)

    high_points = min(7 * len(high_matches), 50)
    medium_points = min(5 * len(medium_matches), 30)
    low_points = min(2 * len(low_matches), 10)
    total_points = high_points + medium_points + low_points

    matched = {
        "high": sorted(high_matches),
        "medium": sorted(medium_matches),
        "low": sorted(low_matches),
    }
    return total_points, matched


def score_age(age_years: Optional[int]) -> int:
    """Score based on subdomain age."""
    if age_years is None:
        return 0
    if age_years >= 10:
        return 10
    if age_years >= 5:
        return 5
    if age_years >= 2:
        return 3
    return 1


def _age_years_from_date(first_seen) -> int:
    today = datetime.now(timezone.utc).date()
    return max(0, (today - first_seen).days // 365)


# =====================================================================
# Liveness
# =====================================================================
@dataclass
class Liveness:
    is_live: bool
    status_code: int
    headers: Dict[str, str]
    final_url: str
    protocol: str


# =====================================================================
# Analyzer
# =====================================================================
@dataclass
class Config:
    """Runtime configuration for :class:`Analyzer`."""

    offline: bool = False
    timeout: float = REQUEST_TIMEOUT
    retries: int = 2
    rate: float = DEFAULT_RATE
    cache_dir: Optional[str] = None
    cache_ttl: int = DEFAULT_CACHE_TTL
    no_cache: bool = False
    threads: int = 10
    top: int = 0
    explain: bool = False
    verbose: bool = False
    quiet: bool = False
    skip_gau: bool = False
    skip_age: bool = False
    skip_wappalyzer: bool = False
    skip_liveness: bool = False
    gau_timeout: float = DEFAULT_GAU_TIMEOUT


class Analyzer:
    """Thread-safe subdomain analyzer with cache and rate limiting."""

    def __init__(
        self,
        config: Config,
        client: Optional[NetworkClient] = None,
        cache: Optional[DiskCache] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self.logger = logger or LOGGER
        self.client = client or NetworkClient(
            timeout=config.timeout, retries=config.retries, rate=config.rate
        )
        if cache is not None:
            self.cache: Optional[DiskCache] = cache
        elif config.no_cache or config.offline:
            self.cache = None
        else:
            self.cache = DiskCache(config.cache_dir, config.cache_ttl)

        self._wappalyzer_lock = threading.Lock()
        self._gau_lock = threading.Lock()
        self._gau_checked = False
        self._gau_path: Optional[str] = None
        self.wappalyzer = None
        if not (config.offline or config.skip_wappalyzer):
            self._init_wappalyzer()

    # -- setup ---------------------------------------------------------
    def _init_wappalyzer(self) -> None:
        if not WAPPALYZER_AVAILABLE:
            if not self.config.quiet:
                self.logger.warning(
                    "python-Wappalyzer not installed; skipping technology detection"
                )
            return
        try:
            self.wappalyzer = Wappalyzer.latest()
        except Exception as exc:  # pragma: no cover - environment dependent
            self.logger.warning("Wappalyzer init failed: %s", exc)
            self.wappalyzer = None

    def _cached(self, kind: str, host: str, fetch):
        """Return a cached value or run ``fetch`` and cache its result."""
        if self.cache is None:
            return fetch()
        key = f"v{SCHEMA_VERSION}:{kind}:{host}"
        hit, value = self.cache.get(key)
        if hit:
            self.logger.debug("cache hit: %s", key)
            return value
        value = fetch()
        self.cache.set(key, value)
        return value

    # -- network -------------------------------------------------------
    def check_liveness(self, subdomain: str) -> Liveness:
        """Check HTTP/HTTPS reachability, preferring HTTPS."""
        url_host = _url_host(subdomain)
        for protocol in ("https", "http"):
            url = f"{protocol}://{url_host}"
            try:
                response = self.client.get(
                    url, allow_redirects=True, verify=False
                )
                return Liveness(
                    True,
                    response.status_code,
                    dict(response.headers),
                    response.url,
                    protocol,
                )
            except requests.exceptions.RequestException as exc:
                self.logger.debug("%s unreachable over %s: %s", subdomain, protocol, exc)
        return Liveness(False, 0, {}, "", "")

    def fetch_historical_urls(
        self, subdomain: str, max_urls: int = 50000
    ) -> List[str]:
        """Fetch historical URLs via ``gau`` (timeout, no shell, cached)."""
        if self.config.offline:
            return []

        gau_path = self._find_gau()
        if gau_path is None:
            return []

        def run() -> List[str]:
            self.client.limiter.wait()
            try:
                proc = subprocess.run(
                    [gau_path, "--", subdomain],
                    capture_output=True,
                    text=True,
                    timeout=self.config.gau_timeout,
                    check=False,
                    shell=False,
                )
            except subprocess.TimeoutExpired:
                self.logger.warning(
                    "gau timed out after %.0fs for %s", self.config.gau_timeout, subdomain
                )
                return []
            except OSError as exc:
                self.logger.warning("gau could not be executed for %s: %s", subdomain, exc)
                return []
            if proc.returncode != 0 and not proc.stdout.strip():
                stderr_lines = (proc.stderr or "").strip().splitlines()
                reason = stderr_lines[-1] if stderr_lines else "no output"
                self.logger.warning(
                    "gau exited with code %d for %s: %s",
                    proc.returncode,
                    subdomain,
                    reason,
                )
                return []
            urls = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
            return sorted(urls)[:max_urls]

        return self._cached("gau", subdomain, run)

    def _find_gau(self) -> Optional[str]:
        with self._gau_lock:
            if not self._gau_checked:
                self._gau_path = shutil.which("gau")
                self._gau_checked = True
                if self._gau_path is None:
                    self.logger.warning(
                        "gau not found in PATH; skipping historical URL analysis"
                    )
            return self._gau_path

    def _fetch_age(self, subdomain: str) -> Optional[List[object]]:
        for method, finder in (
            ("Wayback Machine", self._wayback_age),
            ("crt.sh", self._crtsh_age),
        ):
            first_seen = finder(subdomain)
            if first_seen is not None:
                return [_age_years_from_date(first_seen), first_seen.isoformat(), method]
        return None

    def _wayback_age(self, subdomain: str):
        params = {
            "url": subdomain,
            "output": "json",
            "limit": "1",
            "filter": "statuscode:200",
            "from": "1996",
        }
        try:
            response = self.client.get(WAYBACK_CDX_URL, params=params)
            if response.status_code != 200:
                return None
            rows = response.json()
            if not isinstance(rows, list) or len(rows) < 2:
                return None
            timestamp = str(rows[1][1])
            if not re.fullmatch(r"\d{14}", timestamp):
                return None
            return datetime.strptime(timestamp, "%Y%m%d%H%M%S").date()
        except (requests.exceptions.RequestException, ValueError, TypeError, IndexError) as exc:
            self.logger.debug("Wayback lookup failed for %s: %s", subdomain, exc)
            return None

    def _crtsh_age(self, subdomain: str):
        params = {"q": f"%.{subdomain}", "output": "json"}
        try:
            response = self.client.get(CRTSH_URL, params=params)
            if response.status_code != 200:
                return None
            rows = response.json()
            if not isinstance(rows, list):
                return None
            dates = []
            for row in rows:
                if not isinstance(row, dict):
                    continue
                value = str(row.get("not_before", "")).strip()[:10]
                if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                    try:
                        dates.append(datetime.strptime(value, "%Y-%m-%d").date())
                    except ValueError:
                        continue
            return min(dates) if dates else None
        except (requests.exceptions.RequestException, ValueError, TypeError) as exc:
            self.logger.debug("crt.sh lookup failed for %s: %s", subdomain, exc)
            return None

    def get_subdomain_age(self, subdomain: str) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """Estimate age via Wayback then crt.sh, cached with TTL."""
        if self.config.offline:
            return None, None, None
        value = self._cached("age", subdomain, lambda: self._fetch_age(subdomain))
        if not value:
            return None, None, None
        try:
            return int(value[0]), str(value[1]), str(value[2])
        except (TypeError, ValueError, IndexError):
            return None, None, None

    def analyze_technologies(self, subdomain: str) -> Tuple[int, List[str]]:
        """Fingerprint a site using the shared rate-limited client."""
        if self.wappalyzer is None or self.config.offline:
            return 0, []

        response = None
        url_host = _url_host(subdomain)
        for protocol in ("https", "http"):
            try:
                candidate = self.client.get(
                    f"{protocol}://{url_host}", allow_redirects=True, verify=False
                )
                response = candidate
                break
            except requests.exceptions.RequestException as exc:
                self.logger.debug(
                    "technology fetch failed for %s over %s: %s", subdomain, protocol, exc
                )
        if response is None:
            return 0, []

        try:
            with self._wappalyzer_lock:
                webpage = self._build_webpage(response)
                if hasattr(self.wappalyzer, "analyze_with_versions_and_categories"):
                    detected = self.wappalyzer.analyze_with_versions_and_categories(webpage)
                else:  # pragma: no cover - old python-Wappalyzer
                    detected = self.wappalyzer.analyze(webpage)
        except Exception as exc:
            self.logger.debug("technology detection failed for %s: %s", subdomain, exc)
            return 0, []

        technologies = sorted(str(name) for name in detected)
        points = sum(TECHNOLOGY_POINTS.get(name.lower(), 2) for name in technologies)
        return min(points, TECH_CAP), technologies

    @staticmethod
    def _build_webpage(response):
        try:
            return WebPage(url=response.url, html=response.text, headers=dict(response.headers))
        except TypeError:  # pragma: no cover - older constructors
            return WebPage.new_from_html(response.text)

    # -- analysis ------------------------------------------------------
    def analyze(self, subdomain: str) -> Dict[str, object]:
        """Analyze one subdomain and return a schema-stable result dict."""
        if self.config.offline:
            return self._analyze_offline(subdomain)

        status_code: Optional[int] = 0
        is_live: Optional[bool] = True
        final_url = ""
        header_issues: List[str] = []
        signals: List[Signal] = []

        if not self.config.skip_liveness:
            liveness = self.check_liveness(subdomain)
            status_code = liveness.status_code
            is_live = liveness.is_live
            final_url = liveness.final_url
            if not liveness.is_live:
                return self._build_result(
                    subdomain,
                    [_signal("liveness", 0, "no HTTP response")],
                    severity="DEAD",
                    is_live=False,
                    status_code=0,
                )
            signals.append(
                _signal(
                    "status_code",
                    score_status_code(liveness.status_code),
                    f"HTTP {liveness.status_code}",
                )
            )
            header_points, header_issues = score_security_headers(liveness.headers)
            header_detail = (
                _truncate(header_issues, 8)
                if header_issues
                else "all checked headers present"
            )
            signals.append(_signal("security_headers", header_points, header_detail))

        keyword = keyword_signal(subdomain)
        signals.append(keyword)
        _, matched_keywords = analyze_subdomain_name(subdomain)

        matched_paths = {"high": [], "medium": [], "low": []}
        if not self.config.skip_gau:
            urls = self.fetch_historical_urls(subdomain)
            if urls:
                path_points, matched_paths = analyze_urls(urls)
                detail = (
                    f"{len(matched_paths['high'])} high / "
                    f"{len(matched_paths['medium'])} medium / "
                    f"{len(matched_paths['low'])} low from {len(urls)} URLs"
                )
                signals.append(_signal("paths", path_points, detail))

        technologies: List[str] = []
        if self.wappalyzer is not None:
            tech_points, technologies = self.analyze_technologies(subdomain)
            detail = _truncate(technologies, 10) if technologies else "no technologies detected"
            signals.append(_signal("technology", tech_points, detail))

        age_years: Optional[int] = None
        age_date: Optional[str] = None
        age_method: Optional[str] = None
        if not self.config.skip_age:
            age_years, age_date, age_method = self.get_subdomain_age(subdomain)
            age_points = score_age(age_years)
            if age_years is None:
                detail = "unknown (no Wayback/crt.sh data)"
            else:
                detail = f"{age_years} years since {age_date} via {age_method}"
            signals.append(_signal("age", age_points, detail))

        return self._build_result(
            subdomain,
            signals,
            is_live=is_live,
            status_code=status_code,
            final_url=final_url,
            matched_keywords=matched_keywords,
            matched_paths=matched_paths,
            technologies=technologies,
            age_years=age_years,
            header_issues=header_issues,
        )

    def _analyze_offline(self, subdomain: str) -> Dict[str, object]:
        keyword = keyword_signal(subdomain)
        _, matched = analyze_subdomain_name(subdomain)
        return self._build_result(
            subdomain,
            [keyword],
            is_live=None,
            status_code=None,
            matched_keywords=matched,
        )

    def _build_result(
        self,
        subdomain: str,
        signals: List[Signal],
        *,
        severity: Optional[str] = None,
        is_live: Optional[bool] = None,
        status_code: Optional[int] = None,
        final_url: str = "",
        matched_keywords: Optional[List[str]] = None,
        matched_paths: Optional[Dict[str, List[str]]] = None,
        technologies: Optional[List[str]] = None,
        age_years: Optional[int] = None,
        header_issues: Optional[List[str]] = None,
        error: Optional[str] = None,
    ) -> Dict[str, object]:
        breakdown = empty_breakdown()
        for item in signals:
            if item.name in breakdown:
                breakdown[item.name] = item.points
        score = clamp_score(sum(item.points for item in signals))
        result: Dict[str, object] = {
            "subdomain": subdomain,
            "score": score,
            "severity": severity or classify_severity(score),
            "signals": [item.as_dict() for item in signals],
            "status_code": status_code,
            "tech": sorted(technologies or []),
            "age_years": age_years,
            "is_live": is_live,
            "final_url": final_url,
            "matched_keywords": sorted(matched_keywords or []),
            "matched_paths": matched_paths
            or {"high": [], "medium": [], "low": []},
            "security_header_issues": list(header_issues or []),
            "score_breakdown": breakdown,
            # Deprecated alias kept for v1 consumers.
            "total_points": score,
        }
        if error is not None:
            result["error"] = error
        return result

    def analyze_many(self, subdomains: Iterable[str]) -> List[Dict[str, object]]:
        """Analyze hosts concurrently and return results in stable order."""
        hosts = list(subdomains)
        if not hosts:
            return []
        workers = min(max(1, self.config.threads), len(hosts))
        results: List[Dict[str, object]] = []
        start_time = time.monotonic()

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_host = {
                executor.submit(self.analyze, host): host for host in hosts
            }
            for index, future in enumerate(as_completed(future_to_host), start=1):
                host = future_to_host[future]
                try:
                    result = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    self.logger.error("Error processing %s: %s", host, exc)
                    result = self._build_result(
                        host, [], severity="ERROR", error=str(exc)
                    )
                results.append(result)
                self._report_progress(index, len(hosts), host, result, start_time)

        return sort_results(results)

    def _report_progress(
        self,
        index: int,
        total: int,
        host: str,
        result: Dict[str, object],
        start_time: float,
    ) -> None:
        if self.config.quiet:
            return
        elapsed = max(time.monotonic() - start_time, 0.001)
        rate = index / elapsed
        eta_seconds = (total - index) / rate if rate > 0 else 0
        eta = time.strftime("%H:%M:%S", time.gmtime(eta_seconds))
        print(
            f"  [{index}/{total} | {rate:.1f} subs/s | ETA: {eta}] "
            f"{host} -> [{result['severity']}] {result['score']}pts",
            file=sys.stderr,
        )


def sort_results(results: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    """Sort by severity, then score descending, then hostname."""
    rank = {name: index for index, name in enumerate(SEVERITY_ORDER)}

    def key(result: Dict[str, object]):
        severity = str(result.get("severity", "ERROR"))
        return (
            rank.get(severity, len(SEVERITY_ORDER)),
            -int(result.get("score", 0)),
            str(result.get("subdomain", "")),
        )

    return sorted(results, key=key)


# =====================================================================
# Report generation
# =====================================================================
CSV_FIELDS = (
    "subdomain",
    "score",
    "severity",
    "is_live",
    "status_code",
    "age_years",
    "tech",
    "signals",
    "high_risk_paths",
    "medium_risk_paths",
    "low_risk_paths",
)


@contextmanager
def _open_output(path: str):
    if path == "-":
        yield sys.stdout
        return
    with open(path, "w", encoding="utf-8", newline="") as handle:
        yield handle


def _ranked_eligible(results: List[Dict[str, object]]) -> List[Dict[str, object]]:
    """Return non-DEAD/ERROR results ordered by score, then hostname."""
    eligible = [
        result for result in results if result.get("severity") not in ("DEAD", "ERROR")
    ]
    return sorted(
        eligible,
        key=lambda result: (
            -int(result.get("score", 0)),
            str(result.get("subdomain", "")),
        ),
    )


def json_report_payload(
    results: List[Dict[str, object]],
    top_n: int = 0,
    generated_at: Optional[str] = None,
) -> Dict[str, object]:
    """Build the stable top-level JSON object."""
    payload: Dict[str, object] = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at or utc_now_iso(),
        "total_analyzed": len(results),
        "results": results,
    }
    if top_n > 0:
        payload["top_n"] = top_n
        payload["top"] = [
            result["subdomain"] for result in _ranked_eligible(results)[:top_n]
        ]
    return payload


def write_json_report(
    results: List[Dict[str, object]], output_path: str, top_n: int = 0
) -> str:
    """Write the versioned JSON report."""
    payload = json_report_payload(results, top_n=top_n)
    with _open_output(output_path) as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return output_path


def write_csv_report(results: List[Dict[str, object]], output_path: str) -> str:
    """Write a CSV report, including a header row when there are no results."""
    with _open_output(output_path) as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for result in results:
            matched_paths = result.get("matched_paths") or {}
            signals = result.get("signals") or []
            writer.writerow(
                {
                    "subdomain": result.get("subdomain", ""),
                    "score": result.get("score", 0),
                    "severity": result.get("severity", ""),
                    "is_live": result.get("is_live"),
                    "status_code": result.get("status_code"),
                    "age_years": result.get("age_years"),
                    "tech": "; ".join(result.get("tech") or []),
                    "signals": "; ".join(
                        f"{item['name']}={item['points']}"
                        for item in signals
                        if isinstance(item, dict)
                    ),
                    "high_risk_paths": "; ".join(matched_paths.get("high", [])),
                    "medium_risk_paths": "; ".join(matched_paths.get("medium", [])),
                    "low_risk_paths": "; ".join(matched_paths.get("low", [])),
                }
            )
    return output_path


def format_explanation(result: Dict[str, object]) -> str:
    """Render a human-readable score breakdown."""
    lines = [
        f"{result.get('subdomain', '?')} -> score {result.get('score', 0)} "
        f"({result.get('severity', '?')})"
    ]
    signals = result.get("signals") or []
    if not signals:
        lines.append("  (no scoring signals)")
    for item in signals:
        if not isinstance(item, dict):
            continue
        lines.append(
            f"  {str(item.get('name', '?')):<18} "
            f"+{int(item.get('points', 0)):<3} {item.get('detail', '')}"
        )
    lines.append(f"  {'TOTAL':<18} {int(result.get('score', 0)):<4} (clamped 0-100)")
    return "\n".join(lines)


def write_txt_report(results: List[Dict[str, object]], output_path: str) -> str:
    """Write the human-readable text report including score breakdowns."""
    counts: Dict[str, int] = {}
    for result in results:
        severity = str(result.get("severity", "UNKNOWN"))
        counts[severity] = counts.get(severity, 0) + 1

    with _open_output(output_path) as handle:
        handle.write("=" * 70 + "\n")
        handle.write(f"  SUBDOMAIN ANALYSIS REPORT — {TOOL_NAME} {VERSION}\n")
        handle.write(f"  Generated: {utc_now_iso()}\n")
        handle.write(f"  Total subdomains analyzed: {len(results)}\n")
        handle.write("=" * 70 + "\n\n")

        handle.write("SEVERITY SUMMARY:\n")
        for severity in SEVERITY_ORDER:
            count = counts.get(severity, 0)
            if count:
                handle.write(f"  {severity:10s}: {count}\n")
        handle.write("\n" + "-" * 70 + "\n\n")

        for result in results:
            severity = str(result.get("severity", "UNKNOWN"))
            subdomain = str(result.get("subdomain", ""))
            if severity in ("DEAD", "ERROR"):
                note = result.get("error", "no HTTP response")
                handle.write(f"[{severity}] {subdomain} ({note})\n")
                handle.write("-" * 70 + "\n")
                continue

            handle.write(f"[{severity:8s}] {subdomain}\n")
            handle.write(f"  Score           : {result.get('score', 0)} / 100\n")
            handle.write(
                f"  Live            : {result.get('is_live')} "
                f"(HTTP {result.get('status_code')})\n"
            )
            keywords = result.get("matched_keywords") or []
            handle.write(
                f"  Keywords        : {', '.join(keywords) if keywords else 'None'}\n"
            )

            matched_paths = result.get("matched_paths") or {}
            if matched_paths.get("high"):
                handle.write(f"  High-Risk Paths : {_truncate(matched_paths['high'], 10)}\n")
            if matched_paths.get("medium"):
                handle.write(f"  Med-Risk Paths  : {_truncate(matched_paths['medium'], 10)}\n")

            technologies = result.get("tech") or []
            handle.write(
                f"  Technologies    : {', '.join(technologies) if technologies else 'None'}\n"
            )
            age_years = result.get("age_years")
            handle.write(f"  Age             : {age_years if age_years is not None else 'Unknown'}\n")

            header_issues = result.get("security_header_issues") or []
            if header_issues:
                handle.write(f"  Header Issues   : {_truncate(header_issues, 5)}\n")

            handle.write("  Score Breakdown :\n")
            for item in result.get("signals") or []:
                if not isinstance(item, dict):
                    continue
                handle.write(
                    f"    {str(item.get('name', '?')):<18} "
                    f"+{int(item.get('points', 0)):<3} {item.get('detail', '')}\n"
                )
            handle.write(f"    {'TOTAL':<18} {int(result.get('score', 0)):<4} (clamped 0-100)\n")
            handle.write("-" * 70 + "\n")
    return output_path


def write_top_n_targets(
    results: List[Dict[str, object]], output_path: str, limit: int
) -> str:
    """Write a top-N hostname list for pipeline tools."""
    eligible = _ranked_eligible(results)
    with _open_output(output_path) as handle:
        for result in eligible[:limit]:
            handle.write(f"{result.get('subdomain', '')}\n")
    return output_path


def apply_extension(path: str, fmt: str) -> str:
    """Ensure the output path has the extension for the chosen format."""
    if path == "-":
        return path
    parsed = Path(path)
    desired = f".{fmt}"
    if parsed.suffix.lower() == desired:
        return str(parsed)
    if parsed.suffix:
        return str(parsed.with_suffix(desired))
    return f"{path}{desired}"


# =====================================================================
# CLI
# =====================================================================
def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def _non_negative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def _positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subdomain-analyzer",
        description="Subdomain Analyzer & Scoring System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  subdomain-analyzer -i subs.txt -o report.txt -f txt -t 10
  subdomain-analyzer -i subs.txt -o report.json -f json --explain
  subdomain-analyzer -i - -o - -f json --offline < subs.txt
""",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {VERSION}"
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Input file with subdomains, or - for stdin",
    )
    parser.add_argument(
        "-o", "--output", required=True,
        help="Output report path, or - for stdout",
    )
    parser.add_argument(
        "-f", "--format", choices=("txt", "json", "csv"), default="txt",
        help="Output format: txt (default), json, or csv",
    )
    parser.add_argument(
        "-t", "--threads", type=_positive_int, default=10,
        help="Number of concurrent threads (default: 10)",
    )
    parser.add_argument(
        "--top", type=_non_negative_int, default=0,
        help="Also write a top-N hostname file (0 = disabled)",
    )
    parser.add_argument(
        "--timeout", type=_positive_float, default=REQUEST_TIMEOUT,
        help="HTTP timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--retries", type=_non_negative_int, default=2,
        help="HTTP retries for transient failures (default: 2)",
    )
    parser.add_argument(
        "--rate", type=_positive_float, default=DEFAULT_RATE,
        help="Outbound requests per second, shared by all calls (default: 5)",
    )
    parser.add_argument(
        "--cache-dir", default=None,
        help="Cache directory (default: ~/.cache/subdomain-analyzer)",
    )
    parser.add_argument(
        "--cache-ttl", type=_non_negative_int, default=DEFAULT_CACHE_TTL,
        help="Cache TTL in seconds; 0 disables expiry (default: 86400)",
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Disable the on-disk cache",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="Skip all network calls and score from the hostname alone",
    )
    parser.add_argument(
        "--explain", action="store_true",
        help="Print per-signal score explanations to stderr",
    )
    parser.add_argument(
        "--skip-wappalyzer", "--no-wappalyzer", dest="skip_wappalyzer",
        action="store_true", help="Skip Wappalyzer technology detection",
    )
    parser.add_argument(
        "--skip-age", action="store_true",
        help="Skip subdomain age lookups (Wayback + crt.sh)",
    )
    parser.add_argument(
        "--skip-gau", "--no-gau", dest="skip_gau", action="store_true",
        help="Skip gau historical URL fetching",
    )
    parser.add_argument(
        "--skip-liveness", action="store_true",
        help="Skip the HTTP liveness pre-check",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose (debug) logging on stderr",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress progress output (errors still go to stderr)",
    )
    return parser


def parse_arguments(argv: Optional[List[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure logging to stderr only. Machine output is never logged."""
    LOGGER.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    LOGGER.addHandler(handler)
    LOGGER.propagate = False
    if quiet:
        LOGGER.setLevel(logging.ERROR)
    elif verbose:
        LOGGER.setLevel(logging.DEBUG)
    else:
        LOGGER.setLevel(logging.INFO)


def _emit(message: str, quiet: bool) -> None:
    if not quiet:
        print(message, file=sys.stderr)


def run(args: argparse.Namespace) -> int:
    """Execute the analyzer. Returns a process exit code."""
    setup_logging(args.verbose, args.quiet)

    if args.offline:
        args.skip_wappalyzer = True
        args.skip_age = True
        args.skip_gau = True
        args.skip_liveness = True

    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:  # pragma: no cover - urllib3 always ships with requests
        pass

    subdomains = load_subdomains(args.input)
    if not subdomains:
        LOGGER.error("No valid subdomains found in %s", args.input)
        return 2

    _emit(f"[*] Loaded {len(subdomains)} unique subdomains", args.quiet)
    if args.offline:
        _emit("[*] Offline mode: no network calls will be made", args.quiet)

    config = Config(
        offline=args.offline,
        timeout=args.timeout,
        retries=args.retries,
        rate=args.rate,
        cache_dir=args.cache_dir,
        cache_ttl=args.cache_ttl,
        no_cache=args.no_cache,
        threads=args.threads,
        top=args.top,
        explain=args.explain,
        verbose=args.verbose,
        quiet=args.quiet,
        skip_gau=args.skip_gau,
        skip_age=args.skip_age,
        skip_wappalyzer=args.skip_wappalyzer,
        skip_liveness=args.skip_liveness,
    )

    analyzer = Analyzer(config)
    if analyzer.wappalyzer is not None:
        _emit("[*] Wappalyzer initialized", args.quiet)
    _emit(f"[*] Starting analysis with {args.threads} threads...", args.quiet)

    start_time = time.monotonic()
    results = analyzer.analyze_many(subdomains)
    elapsed = time.strftime("%H:%M:%S", time.gmtime(time.monotonic() - start_time))
    _emit(f"[*] Analysis complete in {elapsed}", args.quiet)

    output_path = apply_extension(args.output, args.format)
    try:
        if args.format == "json":
            write_json_report(results, output_path, top_n=args.top)
        elif args.format == "csv":
            write_csv_report(results, output_path)
        else:
            write_txt_report(results, output_path)
    except OSError as exc:
        LOGGER.error("Error writing report: %s", exc)
        return 1

    _emit(f"[+] Report saved: {output_path}", args.quiet)

    if args.top > 0:
        if output_path == "-":
            LOGGER.warning("--top requires a file output path; skipping top-N file")
        else:
            base = os.path.splitext(output_path)[0]
            top_path = f"{base}_top{args.top}.txt"
            try:
                write_top_n_targets(results, top_path, args.top)
            except OSError as exc:
                LOGGER.error("Error writing top-%d file: %s", args.top, exc)
                return 1
            _emit(f"[+] Top-{args.top}: {top_path}", args.quiet)

    if args.explain:
        for result in results:
            print(format_explanation(result), file=sys.stderr)

    counts: Dict[str, int] = {}
    for result in results:
        severity = str(result.get("severity", "UNKNOWN"))
        counts[severity] = counts.get(severity, 0) + 1
    parts = [f"{counts[name]} {name}" for name in SEVERITY_ORDER if counts.get(name)]
    _emit(f"[*] Summary: {' | '.join(parts) if parts else 'no results'}", args.quiet)

    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point."""
    args = parse_arguments(argv)
    try:
        return run(args)
    except InputError as exc:
        LOGGER.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        LOGGER.error("Interrupted")
        return 1
    except Exception as exc:  # pragma: no cover - defensive
        LOGGER.debug("Fatal error", exc_info=True)
        LOGGER.error("Fatal error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
