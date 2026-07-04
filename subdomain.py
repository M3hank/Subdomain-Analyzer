#!/usr/bin/env python3
"""
Subdomain Analyzer & Scoring System — Elite Bug Bounty Edition

Analyzes subdomains across multiple attack-surface signals and produces
a prioritized, severity-tiered report in TXT, JSON, and CSV formats.

Signals scored:
  - Subdomain name keywords (admin, dev, staging, etc.)
  - Historical URL paths (via gau) matched by prefix against risk tiers
  - Technology fingerprinting (Wappalyzer) with version awareness
  - Subdomain age (crt.sh + Wayback Machine)
  - HTTP liveness + status code analysis
  - Security header posture (HSTS, CSP, X-Frame-Options, CORS)

Usage:
  python3 analyzer.py -i subdomains.txt -o report
  python3 analyzer.py -i subdomains.txt -o report -v --threads 20

Output files created:
  report.txt   — human-readable ranked report
  report.json  — full JSON for pipeline integration
  report.csv   — spreadsheet-friendly summary
"""

import argparse
import json
import logging
import math
import os
import re
import subprocess
import sys
import warnings
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import partial
from urllib.parse import urlparse
import sys
import threading
import time

VERSION = "1.1.0"
import requests
import tldextract

# Optional: Wappalyzer may not be installed
try:
    from Wappalyzer import Wappalyzer, WebPage
    WAPPALYZER_AVAILABLE = True
except ImportError:
    WAPPALYZER_AVAILABLE = False

# ---------------------------------------------------------------------------
# Suppress noisy warnings
# ---------------------------------------------------------------------------
warnings.filterwarnings(
    "ignore",
    message=".*unbalanced parenthesis at position 119.*",
    category=UserWarning,
    module="Wappalyzer"
)

# ---------------------------------------------------------------------------
# Constants — Request Configuration
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = (5, 15)          # (connect, read) seconds
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
REQUEST_HEADERS = {"User-Agent": USER_AGENT}

# ---------------------------------------------------------------------------
# Rate limiter for external APIs (crt.sh, Wayback)
# ---------------------------------------------------------------------------
class RateLimiter:
    """Simple token-bucket rate limiter — thread-safe."""
    def __init__(self, calls_per_second=2):
        self._min_interval = 1.0 / calls_per_second
        self._last_call = 0.0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_call = time.monotonic()

# Global rate limiters

_wayback_limiter = RateLimiter(calls_per_second=3)

# ---------------------------------------------------------------------------
# Subdomain Keywords (deduplicated)
# ---------------------------------------------------------------------------
SUBDOMAIN_KEYWORDS = sorted(set([
    # Administrative and Login Portals
    'admin', 'administrator', 'root', 'backend', 'cpanel', 'controlpanel',
    'dashboard', 'manage', 'sysadmin', 'console', 'login', 'auth', 'sso',
    'oauth', 'account', 'user', 'profile', 'portal',

    # Development and Testing Environments
    'dev', 'development', 'test', 'stage', 'staging', 'qa', 'sandbox',
    'beta', 'alpha', 'preprod', 'prod', 'uat', 'preview',

    # APIs and Services
    'api', 'graphql', 'rest', 'soap', 'services', 'internal', 'external',
    'app', 'apps', 'mobile', 'ios', 'android', 'microservices',

    # Databases and Storage
    'db', 'database', 'data', 'sql', 'mysql', 'postgres', 'mongodb',
    'redis', 'backup', 'storage', 'filestorage', 'archive',

    # Email and Messaging
    'mail', 'email', 'webmail', 'smtp', 'imap', 'pop3', 'exchange',

    # Networking and Infrastructure
    'vpn', 'proxy', 'gateway', 'firewall', 'router', 'network',
    'loadbalancer', 'lb', 'dns', 'monitor', 'status',

    # Cloud and Virtualization
    'cloud', 'aws', 'azure', 'gcp', 'vm', 'virtual', 'docker',
    'kubernetes', 'k8s', 'container', 'rancher', 'orchestrator',

    # CI/CD
    'ci', 'cd', 'build', 'deploy', 'jenkins', 'gitlab', 'github',
    'bitbucket', 'circleci', 'travis', 'teamcity', 'drone', 'artifactory',

    # Business Applications
    'crm', 'erp', 'sharepoint', 'jira', 'confluence', 'zendesk', 'sap',

    # Finance and Payment Systems
    'payment', 'billing', 'invoice', 'checkout', 'pay', 'banking',
    'transaction', 'wallet', 'merchant', 'ecommerce',

    # HR and Employee Services
    'hr', 'employee', 'staff', 'payroll', 'jobs', 'careers', 'talent',
    'recruitment', 'onboarding', 'people', 'benefits',

    # Legal and Compliance
    'legal', 'compliance', 'audit', 'policy', 'gdpr', 'hipaa', 'ccpa',

    # Customer Support
    'support', 'helpdesk', 'servicedesk', 'ticket',

    # Security
    'security', 'authorize', 'authorization', 'token', 'jwt',
    'password', 'passwd', 'vault', 'secret', 'ssh', 'ssl', 'tls', 'encryption',

    # Miscellaneous High-Value
    'www', 'static', 'assets', 'cdn', 'blog', 'news', 'shop', 'store',
    'm', 'secure', 'private',
]))

# High-value keywords that score higher (attack surface indicators)
HIGH_VALUE_KEYWORDS = frozenset([
    'admin', 'administrator', 'root', 'backend', 'db', 'database',
    'secure', 'server', 'internal', 'login', 'auth', 'sysadmin',
    'portal', 'api', 'dev', 'test', 'staging', 'qa', 'vpn', 'mail',
    'beta', 'preprod', 'prod', 'production', 'dashboard',
    'controlpanel', 'manage', 'management', 'oauth', 'user',
    'accounts', 'profile', 'backup', 'archive', 'monitor', 'status',
    'dns', 'proxy', 'gateway', 'firewall', 'jenkins', 'gitlab',
    'jira', 'confluence', 'graphql', 'console', 'debug', 'vault',
    'secret', 'payment', 'billing', 'cpanel',
])

# ---------------------------------------------------------------------------
# Risk Path Tiers — DEDUPLICATED, NON-OVERLAPPING
# Each path exists in exactly ONE tier. Higher tiers take priority.
# Matching is PREFIX-BASED: /admin matches /admin/users/edit
# ---------------------------------------------------------------------------

# High-Risk Paths — administrative, config exposure, debug, backup
HIGH_RISK_PATHS = [
    # Administrative / Login Interfaces
    '/admin', '/administrator', '/admin_area', '/admin1', '/admin2',
    '/admin123', '/admin-login', '/adminLogin', '/admin_home',
    '/adminpanel', '/admin-console', '/adm', '/admincp', '/admin_site',
    '/admincontrol', '/memberadmin', '/users/admin', '/system_admin',
    '/adminsystem', '/secure/admin', '/secret/admin', '/superuser',
    '/root', '/backend', '/manage', '/management',
    '/staff', '/moderator', '/modcp', '/useradmin',
    '/panel', '/cpanel', '/controlpanel',
    '/login', '/user/login', '/users/login', '/login.php', '/login.html',
    '/login.asp', '/login.aspx', '/signin', '/member/login',
    '/account/login', '/accounts/login', '/customer/login',
    '/client/login', '/portal/login', '/home/login',
    '/user/signin', '/users/signin', '/staff/login',
    '/admin/login', '/admin/auth', '/admin/portal', '/admin/panel',
    '/admin/control', '/admin/index.php', '/admin/index.html',
    '/admin/login.html', '/admin/dashboard', '/admin_page',
    '/login/admin', '/cms/admin', '/admin.html', '/admin.aspx',
    '/admin.php', '/adminLogin.php', '/administrator/login.php',

    # Sensitive Configuration Files
    '/.env', '/config.php', '/config.yaml', '/config.json', '/config.ini',
    '/web.config', '/application.config', '/appsettings.json',
    '/settings.php', '/db_config', '/database.yml', '/db.cfg',
    '/config.old', '/config.bak', '/config~', '/localsettings.php',
    '/wp-config.php', '/config/database.php', '/connections.yml',
    '/config.xml', '/config.jsp', '/config.asp', '/dbconfig.php',
    '/database.ini', '/database.json', '/database.xml',
    '/settings.ini', '/settings.json', '/settings.xml',
    '/app.config', '/application.ini', '/application.json',
    '/config_backup', '/config.old.php', '/config.save.php',
    '/config_backup.php',

    # Backup / Dump Files
    '/backup.sql', '/backup.zip', '/bak.zip', '/backup.tar.gz',
    '/backup_old', '/db_backup', '/database.sql', '/dump.sql',
    '/db.sql', '/db.dump', '/website.zip', '/site_backup',
    '/backup/site', '/backup/home', '/backup/www', '/backup/admin',
    '/backup/config', '/backup/database', '/backup/public_html',

    # Version Control Exposure
    '/.git', '/.git/config', '/.git/HEAD', '/.git/index',
    '/.git/logs', '/.git/refs', '/.git/objects',
    '/.git/COMMIT_EDITMSG', '/.git/FETCH_HEAD', '/.git/ORIG_HEAD',
    '/.git/description', '/.git/info', '/.git/packed-refs',
    '/.svn', '/.svn/wc.db', '/.svn/entries',
    '/.hg', '/.bzr',

    # Debug / Testing Endpoints
    '/debug', '/debugging', '/debug-info', '/phpinfo', '/info.php',
    '/test.php', '/debug.php', '/debug.asp', '/debug/config',
    '/debug/test', '/trace', '/traces', '/devinfo', '/devpanel',
    '/server-status', '/server-info', '/debug.log', '/error.log',
    '/diagnostic',

    # Setup / Install (should never be exposed)
    '/setup', '/install', '/installer', '/installation',
    '/setup.php', '/install.php',
]

# Medium-Risk Paths — APIs, CMS, auth endpoints, monitoring
MEDIUM_RISK_PATHS = [
    # API Endpoints
    '/api', '/graphql', '/rest', '/soap', '/services', '/service',
    '/api/token', '/api/login', '/api/register', '/api/logout',
    '/api/auth', '/api/data', '/api/private', '/api/public',
    '/api/admin', '/api/users', '/api/orders', '/api/v1', '/api/v2',
    '/api/v3', '/rest/v1', '/rest-api', '/api-docs',
    '/swagger', '/swagger-ui', '/openapi', '/redoc', '/api/help',
    '/api/status', '/api/health', '/api/info', '/api/metrics',
    '/api/logs', '/api/debug', '/api/test',
    '/webhook', '/callback', '/auth/callback',

    # CMS Admin Panels
    '/wp-admin', '/wp-login.php', '/wp-content', '/wp-includes',
    '/wp-json', '/joomla', '/drupal', '/magento', '/typo3',
    '/prestashop', '/opencart', '/store/admin', '/shop/admin',
    '/cms/login', '/umbraco', '/silverstripe', '/contao',
    '/concrete5', '/dotnetnuke', '/ghost', '/craft',
    '/processwire', '/statamic', '/expressionengine', '/october',
    '/phpbb', '/vbulletin', '/moodle', '/liferay',

    # Authentication / Authorization
    '/auth', '/authentication', '/authorize', '/session', '/sessions',
    '/token', '/tokens', '/oauth', '/oauth2', '/access', '/jwt',
    '/sso', '/signup', '/register', '/user/signup',
    '/account/logout', '/account/register',
    '/reset-password', '/forgot-password', '/user/password/reset',
    '/user/password/forgot', '/verify', '/validate',
    '/activation', '/auth.php', '/authenticator',
    '/password_reset', '/forgotpassword', '/forgot_pwd',
    '/change_password', '/password/change', '/2fa', '/mfa',
    '/security/login', '/auth/login', '/auth/signin',

    # Monitoring / Metrics
    '/monitor', '/monitoring', '/metrics', '/stats', '/statistics',
    '/analytics', '/report', '/reports', '/uptime', '/incident',
    '/incidents', '/status-report', '/status-page',
    '/grafana', '/prometheus', '/kibana', '/elk', '/zabbix',
    '/newrelic', '/datadog', '/matomo', '/logviewer',
    '/health', '/healthcheck', '/diagnostics',

    # Common Backup Extensions
    '/index.php~', '/index.php.bak', '/index.php.old',
    '/index.php.save', '/index.php.swp', '/index.html~',
    '/index.html.bak', '/index.html.old',
    '/config.php~', '/config.php.bak', '/config.php.old',
    '/config.php.save', '/config.php.swp',
    '/settings.py', '/settings.pyc', '/settings.old', '/settings.bak',
    '/.env.old', '/.env.bak', '/.env.save',
    '/web.config.old', '/web.config.bak',
    '/database.yml~', '/database.yml.bak', '/database.yml.old',

    # Application Files
    '/plugin', '/plugins', '/addon', '/addons',
    '/module', '/modules', '/vendor', '/node_modules',
    '/composer.json', '/package.json', '/yarn.lock',
    '/gulpfile.js', '/gruntfile.js',
]

# Low-Risk Paths — static assets, public pages, info pages
LOW_RISK_PATHS = [
    '/www', '/static', '/assets', '/cdn', '/blog', '/news', '/shop',
    '/store', '/favicon.ico', '/rss', '/feed', '/atom', '/subscribe',
    '/unsubscribe', '/newsletter', '/search', '/autocomplete',
    '/customer-support', '/support-center', '/tickets',
    '/issues', '/track', '/tracking', '/alerts', '/notification',
    '/notifications', '/about', '/contact', '/contact-us', '/contactus',
    '/about-us', '/privacy', '/terms', '/terms-of-service',
    '/legal', '/careers', '/jobs', '/events', '/press', '/faq',
    '/help', '/support', '/docs', '/documentation', '/status',
    '/pricing', '/partners', '/api-keys', '/keys', '/license',
    '/downloads', '/download', '/uploads', '/media', '/public',
    '/cache', '/home', '/main', '/default', '/index', '/welcome',
    '/core', '/include', '/includes', '/inc', '/system', '/sys',
    '/cgi-bin', '/cgi', '/scripts', '/script', '/bin', '/utils',
    '/tools', '/webmail',

    # Cloud / DevOps Config (exposed = finding, but low severity alone)
    '/.aws', '/.azure', '/.env.production', '/.env.development',
    '/.env.local', '/.dockerenv', '/docker-compose.yml',
    '/Jenkinsfile', '/jenkins', '/.circleci', '/.travis.yml',
    '/.gitlab-ci.yml', '/.DS_Store', '/.idea', '/.vscode',
    '/.project', '/.editorconfig', '/azure-pipelines.yml',
    '/bitbucket-pipelines.yml', '/appveyor.yml', '/kubernetes.yml',
    '/helm', '/charts', '/k8s', '/kubernetes', '/docker',
    '/dockerfile', '/docker-compose', '/terraform', '/ansible',
    '/puppet', '/chef', '/salt', '/cloudformation',
    '/s3', '/s3bucket', '/storage', '/bucket',
]

# Sort paths longest-first for correct prefix matching
# (e.g., /admin/login should match before /admin)
HIGH_RISK_PATHS = sorted(set(HIGH_RISK_PATHS), key=len, reverse=True)
MEDIUM_RISK_PATHS = sorted(set(MEDIUM_RISK_PATHS), key=len, reverse=True)
LOW_RISK_PATHS = sorted(set(LOW_RISK_PATHS), key=len, reverse=True)

import re
HIGH_RISK_REGEX = re.compile(r'^(?:' + '|'.join(re.escape(p) for p in HIGH_RISK_PATHS) + r')(?:/|$)')
MEDIUM_RISK_REGEX = re.compile(r'^(?:' + '|'.join(re.escape(p) for p in MEDIUM_RISK_PATHS) + r')(?:/|$)')
LOW_RISK_REGEX = re.compile(r'^(?:' + '|'.join(re.escape(p) for p in LOW_RISK_PATHS) + r')(?:/|$)')

# ---------------------------------------------------------------------------
# Technology Scoring — points based on historical vulnerability density
# ---------------------------------------------------------------------------
TECHNOLOGY_POINTS = {
    # Web Servers
    'apache': 7, 'nginx': 5, 'iis': 8, 'lighttpd': 4, 'caddy': 3,
    'tomcat': 8, 'jetty': 6, 'weblogic': 9, 'websphere': 8,
    'glassfish': 7, 'jboss': 8,

    # Programming Languages
    'php': 9, 'python': 4, 'perl': 6, 'ruby': 5, 'java': 6,
    'asp.net': 8, 'node.js': 7, 'go': 3, 'rust': 2,
    'coldfusion': 9, 'lua': 4, 'elixir': 3, 'clojure': 2,

    # CMS
    'wordpress': 10, 'joomla': 9, 'drupal': 9, 'magento': 10,
    'typo3': 7, 'prestashop': 8, 'opencart': 8, 'shopify': 5,
    'wix': 4, 'weebly': 4, 'squarespace': 4, 'ghost': 5,
    'blogger': 3, 'tumblr': 3,

    # Databases
    'mysql': 8, 'mariadb': 7, 'postgresql': 6, 'mongodb': 9,
    'redis': 7, 'elasticsearch': 9, 'couchdb': 7, 'cassandra': 6,
    'oracle': 7, 'sql server': 8, 'db2': 5, 'hbase': 6,

    # Application Frameworks
    'django': 6, 'flask': 5, 'ruby on rails': 8, 'laravel': 9,
    'symfony': 8, 'express': 7, 'spring': 7, 'struts': 9,
    'codeigniter': 7, 'cakephp': 7, 'zend framework': 7,
    'asp.net mvc': 8,

    # JavaScript Libraries/Frameworks
    'jquery': 5, 'react': 6, 'angular': 7, 'vue.js': 5,
    'ember.js': 5, 'backbone.js': 4, 'dojo': 4, 'extjs': 5,
    'bootstrap': 3, 'semantic ui': 3,

    # Operating Systems
    'windows': 7, 'linux': 4, 'ubuntu': 4, 'centos': 4,
    'red hat': 4, 'debian': 4, 'freebsd': 3, 'openbsd': 3,

    # Containers and Orchestration
    'docker': 7, 'kubernetes': 7, 'openshift': 6, 'mesos': 5,
    'rancher': 5, 'nomad': 4,

    # Authentication and Security
    'oauth': 5, 'saml': 5, 'ldap': 6, 'active directory': 8,
    'okta': 5, 'auth0': 5, 'shibboleth': 6, 'keycloak': 6,
    'forgerock': 6,

    # Miscellaneous
    'ftp': 8, 'sftp': 4, 'telnet': 10, 'ssh': 4, 'rdp': 9,
    'vpn': 7, 'ngrok': 6,
}

# ---------------------------------------------------------------------------
# Security Header Scoring — missing headers = higher score
# ---------------------------------------------------------------------------
SECURITY_HEADERS = {
    'strict-transport-security': 5,   # Missing HSTS
    'content-security-policy': 5,     # Missing CSP
    'x-frame-options': 3,             # Clickjacking
    'x-content-type-options': 2,      # MIME sniffing
    'x-xss-protection': 1,           # Legacy but still checked
    'referrer-policy': 2,            # Info leakage
    'permissions-policy': 2,          # Feature policy
}

# Status codes that indicate interesting attack surface
INTERESTING_STATUS_CODES = {
    401: 8,   # Auth required — potential bypass
    403: 7,   # Forbidden — potential bypass (403 bypass techniques)
    500: 6,   # Server error — potential info leak
    502: 4,   # Bad gateway — potential SSRF indicator
    503: 3,   # Service unavailable — may be rate limited or behind WAF
    405: 5,   # Method not allowed — try other HTTP methods
    301: 2,   # Redirect — potential open redirect
    302: 2,   # Redirect — potential open redirect
    307: 2,   # Redirect — potential open redirect
}


# =====================================================================
# Argument Parsing
# =====================================================================
def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Subdomain Analyzer & Scoring System — Elite Bug Bounty Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 analyzer.py -i subs.txt -o report
  python3 analyzer.py -i subs.txt -o report -v --threads 20 --top 50
  python3 analyzer.py -i subs.txt -o report --skip-wappalyzer --skip-age
        """
    )
    parser.add_argument('-i', '--input', required=True,
                        help='Input file with subdomains (one per line)')
    parser.add_argument('-o', '--output', required=True,
                        help='Output report file path')
    parser.add_argument('-f', '--format', choices=['txt', 'json'], default='txt',
                        help='Output format: txt (default) or json')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--threads', type=int, default=10,
                        help='Number of concurrent threads (default: 10)')
    parser.add_argument('--top', type=int, default=0,
                        help='Also output a top-N targets file for pipeline use (0 = disabled)')
    parser.add_argument('--skip-wappalyzer', action='store_true',
                        help='Skip Wappalyzer technology detection')
    parser.add_argument('--skip-age', action='store_true',
                        help='Skip subdomain age lookups (crt.sh + Wayback)')
    parser.add_argument('--skip-gau', action='store_true',
                        help='Skip gau historical URL fetching')
    parser.add_argument('--skip-liveness', action='store_true',
                        help='Skip HTTP liveness pre-check')
    return parser.parse_args()


# =====================================================================
# Logging Setup
# =====================================================================
def setup_logging(verbose):
    """Configure logging to file + optional console."""
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.handlers = []

    file_handler = logging.FileHandler('subdomain_analyzer.log')
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if verbose:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)


# =====================================================================
# Input Loading
# =====================================================================
def load_subdomains(file_path):
    """Load and deduplicate subdomains from file."""
    subdomains = set()
    try:
        with open(file_path, 'r') as f:
            for line in f:
                subdomain = line.strip().lower()
                if subdomain:
                    subdomains.add(subdomain)
    except FileNotFoundError:
        logging.error(f"Input file not found: {file_path}")
        print(f"Error: Input file not found: {file_path}")
        sys.exit(1)
    return subdomains


# =====================================================================
# HTTP Liveness Check + Header Analysis
# =====================================================================
def check_liveness(subdomain, verbose=False):
    """
    Check if a subdomain is live via HTTP/HTTPS.
    Returns (is_live, status_code, response_headers, final_url, protocol).
    """
    for protocol in ['https', 'http']:
        url = f"{protocol}://{subdomain}"
        try:
            resp = requests.get(
                url,
                headers=REQUEST_HEADERS,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False  # Don't fail on bad certs — we want to analyze them
            )
            if verbose:
                print(f"  [LIVE] {url} -> {resp.status_code}")
            return True, resp.status_code, dict(resp.headers), resp.url, protocol
        except requests.exceptions.SSLError:
            # SSL error on HTTPS — still interesting, try HTTP
            if protocol == 'https':
                continue
            return False, 0, {}, '', ''
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.RequestException):
            continue
    return False, 0, {}, '', ''


def score_status_code(status_code):
    """Score based on HTTP status code interestingness."""
    return INTERESTING_STATUS_CODES.get(status_code, 0)


def score_security_headers(headers, verbose=False):
    """
    Score based on MISSING security headers.
    More missing headers = higher score (= more interesting target).
    """
    points = 0
    missing = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, header_points in SECURITY_HEADERS.items():
        if header not in headers_lower:
            points += header_points
            missing.append(header)

    # Check for permissive CORS
    cors_origin = headers_lower.get('access-control-allow-origin', '')
    cors_creds = headers_lower.get('access-control-allow-credentials', '').lower()
    if cors_origin == '*':
        points += 5
        missing.append('CORS: Access-Control-Allow-Origin: *')
    elif cors_origin and cors_creds == 'true':
        points += 8
        missing.append(f'CORS: origin={cors_origin} with credentials=true')

    if verbose and missing:
        print(f"  Security header issues: {', '.join(missing)} (+{points})")

    return points, missing


# =====================================================================
# Subdomain Name Analysis
# =====================================================================
def analyze_subdomain_name(subdomain):
    """
    Analyze the subdomain string for high-value keywords.
    Returns (points, matched_keywords).
    """
    points = 0
    matched_keywords = set()
    subdomain_part = tldextract.extract(subdomain).subdomain.lower()
    tokens = re.split(r'\W+', subdomain_part)

    for keyword in SUBDOMAIN_KEYWORDS:
        if keyword in tokens:
            matched_keywords.add(keyword)

    for keyword in matched_keywords:
        if keyword in HIGH_VALUE_KEYWORDS:
            points += 5
        else:
            points += 3

    return points, list(matched_keywords)


# =====================================================================
# Historical URL Fetching (gau)
# =====================================================================
def fetch_historical_urls(subdomain, verbose=False, max_urls=50000):
    """
    Fetch historical URLs for a subdomain using `gau`.
    Returns deduplicated list of URLs. Streamed to prevent memory exhaustion.
    """
    if verbose:
        print(f"  Fetching URLs via gau...")

    try:
        proc = subprocess.Popen(
            ['gau', subdomain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        urls = set()
        try:
            for line in proc.stdout:
                url = line.strip()
                if url:
                    urls.add(url)
                    if len(urls) >= max_urls:
                        proc.terminate()
                        break
            proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            logging.warning(f"gau timed out for {subdomain}")
            if verbose:
                print(f"  gau timed out for {subdomain} (collected {len(urls)})")
        
        urls_list = list(urls)
        if verbose:
            print(f"  Fetched {len(urls_list)} unique URLs.")
        return urls_list

    except FileNotFoundError:
        logging.error("'gau' tool not found in PATH.")
        if verbose:
            print("  Error: 'gau' not installed. Skipping URL fetch.")
        return []
    except Exception as e:
        logging.error(f"gau unexpected error for {subdomain}: {e}")
        if verbose:
            print(f"  gau error: {e}")
        return []


# =====================================================================
# URL/Path Risk Analysis — PREFIX MATCHING
# =====================================================================
def _normalize_path(url):
    """Extract and normalize the path from a URL."""
    parsed_path = re.sub(r'\?.*$', '', url)
    parsed_path = re.sub(r'http[s]?://[^/]+', '', parsed_path)
    parsed_path = parsed_path.lower().rstrip('/')
    return parsed_path if parsed_path else '/'


def _prefix_match(path, risk_paths):
    """Check if path starts with any risk path (prefix matching)."""
    for risk_path in risk_paths:
        if path == risk_path or path.startswith(risk_path + '/'):
            return True
    return False


def analyze_urls(urls, verbose=False):
    """
    Analyze collected URLs against risk-tiered path lists using PREFIX matching.
    Returns (total_points, matched_paths_dict) with scoring caps.
    """
    high_matches = set()
    medium_matches = set()
    low_matches = set()

    # Extract unique paths
    unique_paths = set()
    for url in urls:
        path = _normalize_path(url)
        if path:
            unique_paths.add(path)

    for path in unique_paths:
        if HIGH_RISK_REGEX.match(path):
            high_matches.add(path)
        elif MEDIUM_RISK_REGEX.match(path):
            medium_matches.add(path)
        elif LOW_RISK_REGEX.match(path):
            low_matches.add(path)

    # Apply diminishing returns (logarithmic capping)
    # First few matches score fully, then taper off
    high_points = min(7 * len(high_matches), 50)       # Cap at 50
    medium_points = min(5 * len(medium_matches), 30)    # Cap at 30
    low_points = min(2 * len(low_matches), 10)          # Cap at 10
    total_points = high_points + medium_points + low_points

    all_matched = {
        'high': sorted(high_matches),
        'medium': sorted(medium_matches),
        'low': sorted(low_matches),
    }

    if verbose:
        if high_matches:
            print(f"  High-risk paths ({len(high_matches)}): {', '.join(list(high_matches)[:5])}{'...' if len(high_matches) > 5 else ''}")
        if medium_matches:
            print(f"  Medium-risk paths ({len(medium_matches)}): {', '.join(list(medium_matches)[:5])}{'...' if len(medium_matches) > 5 else ''}")
        if low_matches:
            print(f"  Low-risk paths ({len(low_matches)}): {', '.join(list(low_matches)[:5])}{'...' if len(low_matches) > 5 else ''}")
        print(f"  Path score: +{total_points} (H:{high_points} M:{medium_points} L:{low_points})")

    return total_points, all_matched


# =====================================================================
# Subdomain Age (Wayback Machine)
# =====================================================================
def get_subdomain_age(subdomain, verbose=False):
    """Estimate subdomain age via Wayback Machine first-capture date."""
    if verbose:
        print(f"  Querying Wayback Machine for age...")

    _wayback_limiter.wait()

    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={subdomain}&output=json&limit=1&filter=statuscode:200&from=1996"
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS)
        if response.status_code == 200:
            data = response.json()
            if len(data) > 1:
                timestamp = data[1][1]
                capture_date = datetime.strptime(timestamp, '%Y%m%d%H%M%S')
                age = datetime.now() - capture_date
                age_years = age.days // 365
                if verbose:
                    print(f"  Wayback: first capture {capture_date.date()} ({age_years}y ago)")
                return age_years, capture_date.date(), 'Wayback Machine'
        return None, None, None
    except Exception as e:
        logging.error(f"Wayback error for {subdomain}: {e}")
        if verbose:
            print(f"  Wayback error: {e}")
        return None, None, None


def score_age(age_years):
    """Score based on subdomain age."""
    if age_years is None:
        return 0
    if age_years >= 10:
        return 10
    elif age_years >= 5:
        return 5
    elif age_years >= 2:
        return 3
    else:
        return 1


# =====================================================================
# Technology Detection (Wappalyzer)
# =====================================================================
def analyze_technologies(wappalyzer, subdomain, verbose=False):
    """
    Detect technologies using Wappalyzer (initialized once, passed in).
    Returns (points, technologies_list).
    """
    if wappalyzer is None:
        return 0, []

    if verbose:
        print(f"  Detecting technologies...")

    tech_points = 0
    technologies = set()
    test_urls = [f"http://{subdomain}", f"https://{subdomain}"]

    for url in test_urls:
        try:
            webpage = WebPage.new_from_url(url, timeout=REQUEST_TIMEOUT[1])
            detected = wappalyzer.analyze_with_versions_and_categories(webpage)
            for tech, info in detected.items():
                if tech not in technologies:
                    technologies.add(tech)
                    points = TECHNOLOGY_POINTS.get(tech.lower(), 2)
                    tech_points += points
                    if verbose:
                        print(f"    {tech} (+{points})")
            break  # Success on first protocol — stop
        except Exception as e:
            if verbose:
                print(f"    Wappalyzer error on {url}: {e}")

    # Cap technology score to prevent tech-heavy sites from dominating
    tech_points = min(tech_points, 60)
    return tech_points, sorted(technologies)


# =====================================================================
# Severity Classification
# =====================================================================
def classify_severity(total_points):
    """Classify subdomain into severity tier based on total score."""
    if total_points >= 50:
        return "CRITICAL"
    elif total_points >= 30:
        return "HIGH"
    elif total_points >= 15:
        return "MEDIUM"
    else:
        return "LOW"


# =====================================================================
# Core Analysis — Single Subdomain
# =====================================================================
def analyze_subdomain(subdomain, wappalyzer=None, verbose=False,
                      skip_gau=False, skip_age=False, skip_wappalyzer=False,
                      skip_liveness=False):
    """Analyze a single subdomain across all signals. Returns result dict."""
    total_points = 0
    result = {
        'subdomain': subdomain,
        'total_points': 0,
        'severity': 'LOW',
        'is_live': False,
        'status_code': 0,
        'final_url': '',
        'matched_keywords': [],
        'matched_paths': {'high': [], 'medium': [], 'low': []},
        'technologies': [],
        'subdomain_age': '',
        'security_header_issues': [],
        'cors_issues': [],
        'score_breakdown': {},
    }

    if verbose:
        print(f"\n{'='*60}\nAnalyzing: {subdomain}\n{'='*60}")

    # --- Liveness Check + Headers ---
    status_points = 0
    header_points = 0
    if not skip_liveness:
        is_live, status_code, headers, final_url, protocol = check_liveness(subdomain, verbose)
        result['is_live'] = is_live
        result['status_code'] = status_code
        result['final_url'] = final_url

        if not is_live:
            if verbose:
                print(f"  [DEAD] {subdomain} — skipping further analysis")
            result['severity'] = 'DEAD'
            return result

        # Score status code
        status_points = score_status_code(status_code)
        total_points += status_points

        # Score security headers
        header_points, header_issues = score_security_headers(headers, verbose)
        total_points += header_points
        result['security_header_issues'] = header_issues
    else:
        result['is_live'] = True  # Assume live if skipping check

    # --- Subdomain Name Keywords ---
    keyword_points, matched_keywords = analyze_subdomain_name(subdomain)
    total_points += keyword_points
    result['matched_keywords'] = matched_keywords
    if verbose and matched_keywords:
        print(f"  Keywords: {', '.join(matched_keywords)} (+{keyword_points})")

    # --- Historical URL Analysis ---
    url_points = 0
    if not skip_gau:
        urls = fetch_historical_urls(subdomain, verbose)
        if urls:
            url_points, matched_paths = analyze_urls(urls, verbose)
            total_points += url_points
            result['matched_paths'] = matched_paths

    # --- Technology Detection ---
    tech_points = 0
    if not skip_wappalyzer and wappalyzer is not None:
        tech_points, technologies = analyze_technologies(wappalyzer, subdomain, verbose)
        total_points += tech_points
        result['technologies'] = technologies

    # --- Subdomain Age ---
    age_points = 0
    if not skip_age:
        age_years, date_used, method_used = get_subdomain_age(subdomain, verbose)
        if age_years is not None:
            age_points = score_age(age_years)
            total_points += age_points
            result['subdomain_age'] = f"{age_years} years (since {date_used}, via {method_used})"
            if verbose:
                print(f"  Age: {age_years}y (+{age_points})")
        else:
            result['subdomain_age'] = "Unknown"

    # --- Finalize ---
    result['total_points'] = total_points
    result['severity'] = classify_severity(total_points)
    result['score_breakdown'] = {
        'keywords': keyword_points,
        'paths': url_points,
        'technology': tech_points,
        'age': age_points,
        'status_code': status_points,
        'security_headers': header_points,
    }

    if verbose:
        print(f"  TOTAL: {total_points} [{result['severity']}]")

    return result


# =====================================================================
# Report Generation
# =====================================================================
def write_txt_report(results, output_path):
    """Write human-readable text report."""
    with open(output_path, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("  SUBDOMAIN ANALYSIS REPORT — Elite Bug Bounty Edition\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Total subdomains analyzed: {len(results)}\n")
        f.write("=" * 70 + "\n\n")

        # Summary stats
        severity_counts = defaultdict(int)
        for r in results:
            severity_counts[r['severity']] += 1

        f.write("SEVERITY SUMMARY:\n")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'DEAD']:
            count = severity_counts.get(sev, 0)
            if count:
                f.write(f"  {sev:10s}: {count}\n")
        f.write("\n" + "-" * 70 + "\n\n")

        for res in results:
            if res['severity'] == 'DEAD':
                f.write(f"[DEAD] {res['subdomain']}\n")
                f.write("-" * 70 + "\n")
                continue

            f.write(f"[{res['severity']:8s}] {res['subdomain']}\n")
            f.write(f"  Score           : {res['total_points']}\n")
            f.write(f"  Breakdown       : {json.dumps(res['score_breakdown'])}\n")
            f.write(f"  Live            : {'Yes' if res['is_live'] else 'No'} (HTTP {res['status_code']})\n")
            f.write(f"  Keywords        : {', '.join(res['matched_keywords']) if res['matched_keywords'] else 'None'}\n")

            high_paths = res['matched_paths'].get('high', [])
            med_paths = res['matched_paths'].get('medium', [])
            if high_paths:
                f.write(f"  High-Risk Paths : {', '.join(high_paths[:10])}{'...' if len(high_paths) > 10 else ''}\n")
            if med_paths:
                f.write(f"  Med-Risk Paths  : {', '.join(med_paths[:10])}{'...' if len(med_paths) > 10 else ''}\n")

            f.write(f"  Technologies    : {', '.join(res['technologies']) if res['technologies'] else 'None'}\n")
            f.write(f"  Age             : {res['subdomain_age']}\n")

            if res['security_header_issues']:
                f.write(f"  Header Issues   : {', '.join(res['security_header_issues'][:5])}\n")

            f.write("-" * 70 + "\n")


def write_json_report(results, output_path):
    """Write full JSON report for pipeline integration."""
    report = {
        'generated': datetime.now().isoformat(),
        'total_analyzed': len(results),
        'results': results,
    }
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)





def write_top_n_targets(results, output_path, n):
    """Write top-N subdomain list for pipeline tools (nuclei, ffuf, etc.)."""
    live_results = [r for r in results if r['severity'] != 'DEAD']
    top = live_results[:n]
    with open(output_path, 'w') as f:
        for r in top:
            f.write(f"{r['subdomain']}\n")


# =====================================================================
# Main
# =====================================================================
def main():
    args = parse_arguments()
    setup_logging(args.verbose)

    # Suppress InsecureRequestWarning for verify=False
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    subdomains = load_subdomains(args.input)
    total_subdomains = len(subdomains)

    print(f"\n[*] Loaded {total_subdomains} subdomains")

    # Initialize Wappalyzer ONCE (thread-safe for reads)
    wappalyzer = None
    if not args.skip_wappalyzer and WAPPALYZER_AVAILABLE:
        try:
            wappalyzer = Wappalyzer.latest()
            print("[*] Wappalyzer initialized")
        except Exception as e:
            logging.error(f"Wappalyzer init failed: {e}")
            print(f"[!] Wappalyzer init failed: {e} — continuing without tech detection")
    elif not WAPPALYZER_AVAILABLE and not args.skip_wappalyzer:
        print("[!] Wappalyzer not installed — skipping tech detection")

    print(f"[*] Starting analysis with {args.threads} threads...\n")
    start_time = time.time()

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_sub = {
            executor.submit(
                analyze_subdomain,
                subdomain,
                wappalyzer=wappalyzer,
                verbose=args.verbose,
                skip_gau=args.skip_gau,
                skip_age=args.skip_age,
                skip_wappalyzer=args.skip_wappalyzer,
                skip_liveness=args.skip_liveness,
            ): subdomain
            for subdomain in subdomains
        }

        for idx, future in enumerate(as_completed(future_to_sub), start=1):
            subdomain = future_to_sub[future]
            
            elapsed = time.time() - start_time
            rate = idx / elapsed if elapsed > 0 else 0
            eta_seconds = (total_subdomains - idx) / rate if rate > 0 else 0
            eta_str = time.strftime("%H:%M:%S", time.gmtime(eta_seconds))
            
            try:
                result = future.result()
                results.append(result)
                severity = result['severity']
                score = result['total_points']
                print(f"  [{idx}/{total_subdomains} | {rate:.1f} subs/s | ETA: {eta_str}] {subdomain} -> [{severity}] {score}pts")
                logging.info(f"Processed {idx}/{total_subdomains}: {subdomain} [{severity}] {score}pts")
            except Exception as e:
                logging.error(f"Error processing {subdomain}: {e}")
                print(f"  [{idx}/{total_subdomains} | {rate:.1f} subs/s | ETA: {eta_str}] {subdomain} -> ERROR: {e}")

    total_elapsed = time.time() - start_time
    total_elapsed_str = time.strftime("%H:%M:%S", time.gmtime(total_elapsed))
    print(f"\n[*] Analysis complete in {total_elapsed_str}")

    # Sort by score descending (DEAD at the bottom)
    results.sort(key=lambda x: (x['severity'] != 'DEAD', x['total_points']), reverse=True)

    # Generate report — TXT (default) or JSON
    output_path = args.output
    # Ensure correct extension
    if args.format == 'json' and not output_path.endswith('.json'):
        output_path = output_path.rsplit('.', 1)[0] + '.json' if '.' in output_path else output_path + '.json'
    elif args.format == 'txt' and not output_path.endswith('.txt'):
        output_path = output_path.rsplit('.', 1)[0] + '.txt' if '.' in output_path else output_path + '.txt'

    try:
        if args.format == 'json':
            write_json_report(results, output_path)
        else:
            write_txt_report(results, output_path)

        print(f"\n[✓] Report saved: {output_path}")

        if args.top > 0:
            base = output_path.rsplit('.', 1)[0]
            top_path = f"{base}_top{args.top}.txt"
            write_top_n_targets(results, top_path, args.top)
            print(f"    Top-{args.top}: {top_path}")

        # Print quick summary
        severity_counts = defaultdict(int)
        for r in results:
            severity_counts[r['severity']] += 1
        print(f"\n[*] Summary: ", end='')
        parts = []
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'DEAD']:
            c = severity_counts.get(sev, 0)
            if c:
                parts.append(f"{c} {sev}")
        print(' | '.join(parts))

        logging.info(f"Analysis complete. Report saved to {output_path}")

    except Exception as e:
        logging.error(f"Error writing report: {e}")
        print(f"Error writing report: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
