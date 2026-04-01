#!/usr/bin/env python3
"""
Subdomain Analyzer & Scoring System
Analyzes subdomains for security-relevant characteristics and assigns risk scores.
"""

import argparse
import csv
import io
import json
import logging
import re
import subprocess
import sys
import threading
import warnings
from collections import defaultdict
from datetime import datetime
from urllib.parse import urlparse

import requests
import tldextract

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

try:
    from Wappalyzer import Wappalyzer, WebPage
    HAS_WAPPALYZER = True
except ImportError:
    HAS_WAPPALYZER = False

# Suppress Wappalyzer warnings
warnings.filterwarnings("ignore", message=".*unbalanced parenthesis.*", category=UserWarning, module="Wappalyzer")

# Thread-safe print lock
_print_lock = threading.Lock()


# ---------------------------------------------------------------------------
# CLI Argument Parsing
# ---------------------------------------------------------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Subdomain Analyzer & Scoring System — Evaluate subdomains for recon prioritization.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python subdomain.py -i subs.txt -o report.json -f json --threads 20 -v",
    )
    parser.add_argument("-i", "--input", required=True, help="Input file with subdomains (one per line)")
    parser.add_argument("-o", "--output", required=True, help="Output report file path")
    parser.add_argument("-f", "--format", choices=["txt", "json", "csv"], default="txt", help="Output format (default: txt)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--no-gau", action="store_true", help="Skip historical URL fetching via gau")
    parser.add_argument("--no-wappalyzer", action="store_true", help="Skip Wappalyzer technology detection")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose console output")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Colored & Thread-safe Output Helpers
# ---------------------------------------------------------------------------
def cprint(msg, color=None):
    """Thread-safe colored print."""
    with _print_lock:
        if HAS_COLOR and color:
            print(f"{color}{msg}{Style.RESET_ALL}")
        else:
            print(msg)


def banner():
    b = r"""
  ____        _         _                       _            
 / ___| _   _| |__   __| | ___  _ __ ___   __ _(_)_ __       
 \___ \| | | | '_ \ / _` |/ _ \| '_ ` _ \ / _` | | '_ \      
  ___) | |_| | |_) | (_| | (_) | | | | | | (_| | | | | |     
 |____/ \__,_|_.__/ \__,_|\___/|_| |_| |_|\__,_|_|_| |_|     
     _                _                                       
    / \   _ __   __ _| |_   _ _______ _ __                    
   / _ \ | '_ \ / _` | | | | |_  / _ \ '__|                   
  / ___ \| | | | (_| | | |_| |/ /  __/ |                      
 /_/   \_\_| |_|\__,_|_|\__, /___\___|_|                      
                        |___/                                  
    """
    if HAS_COLOR:
        print(f"{Fore.CYAN}{b}{Style.RESET_ALL}")
    else:
        print(b)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def setup_logging(verbose):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.handlers = []

    fh = logging.FileHandler("subdomain_analyzer.log")
    fh.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    if verbose:
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(fmt)
        logger.addHandler(ch)


# ---------------------------------------------------------------------------
# Subdomain Keywords (de-duplicated)
# ---------------------------------------------------------------------------
SUBDOMAIN_KEYWORDS = {
    # High-criticality (5 pts)
    'admin', 'administrator', 'root', 'backend', 'cpanel', 'controlpanel',
    'dashboard', 'manage', 'sysadmin', 'console', 'login', 'auth', 'sso',
    'oauth', 'account', 'portal', 'api', 'dev', 'development', 'test',
    'stage', 'staging', 'qa', 'sandbox', 'beta', 'preprod', 'prod',
    'uat', 'db', 'database', 'internal', 'vpn', 'proxy', 'gateway',
    'firewall', 'monitor', 'status', 'dns', 'mail', 'secure', 'private',
    'backup', 'archive',

    # Medium-criticality (3 pts)
    'user', 'profile', 'graphql', 'rest', 'soap', 'services', 'external',
    'app', 'apps', 'mobile', 'ios', 'android', 'microservices',
    'data', 'sql', 'mysql', 'postgres', 'mongodb', 'redis', 'storage',
    'email', 'webmail', 'smtp', 'imap', 'pop3', 'exchange',
    'router', 'network', 'loadbalancer', 'lb',
    'cloud', 'aws', 'azure', 'gcp', 'vm', 'docker',
    'kubernetes', 'k8s', 'container', 'rancher',
    'ci', 'cd', 'build', 'deploy', 'jenkins', 'gitlab', 'github',
    'bitbucket', 'artifactory',
    'crm', 'erp', 'jira', 'confluence', 'sap',
    'payment', 'billing', 'checkout', 'pay', 'banking',
    'hr', 'employee', 'payroll', 'jobs', 'careers',
    'legal', 'compliance', 'audit',
    'support', 'helpdesk', 'ticket',
    'security', 'token', 'vault', 'secret', 'ssh',
    'www', 'static', 'assets', 'cdn', 'blog', 'news', 'shop', 'store',
    'alpha', 'preview', 'm',
}

HIGH_CRIT_KEYWORDS = {
    'admin', 'administrator', 'root', 'backend', 'db', 'database', 'secure',
    'internal', 'login', 'auth', 'sysadmin', 'portal', 'api', 'dev', 'test',
    'staging', 'qa', 'vpn', 'mail', 'beta', 'preprod', 'prod', 'dashboard',
    'controlpanel', 'manage', 'oauth', 'backup', 'archive', 'monitor',
    'status', 'dns', 'proxy', 'gateway', 'firewall', 'private', 'console',
    'cpanel', 'sso', 'account', 'sandbox', 'stage', 'uat', 'development',
}


# ---------------------------------------------------------------------------
# Risk Paths (unchanged but converted to frozensets for speed)
# ---------------------------------------------------------------------------
HIGH_RISK_PATHS = frozenset([
    '/admin', '/administrator', '/admin/login', '/login', '/user/login',
    '/users/login', '/login.php', '/login.html', '/admin/index.php',
    '/admin.html', '/login.asp', '/admin/portal', '/admin/panel',
    '/controlpanel', '/cpanel', '/admin/control', '/manager', '/admin/auth',
    '/admin_area', '/admin1', '/admin2', '/admin123',
    '/administrator/login.php', '/admin-login', '/adminLogin',
    '/admin_home', '/adminpanel', '/admin-console', '/adm',
    '/admin/account', '/admin/dashboard', '/admin_page',
    '/login/admin', '/cms/admin', '/admincp', '/admin_site',
    '/admincontrol', '/memberadmin', '/users/admin', '/system_admin',
    '/adminsystem', '/secure/admin', '/secret/admin', '/superuser',
    '/root', '/backend', '/manage', '/management', '/dashboard',
    '/staff', '/staff/login', '/moderator', '/modcp', '/useradmin',
    '/panel', '/secure', '/signin', '/member', '/members',
    '/member/login', '/account/login', '/accounts/login',
    '/customer/login', '/client/login', '/portal', '/portal/login',
    '/home/login', '/user/signin', '/users/signin', '/login.aspx',
    '/admin.aspx', '/admin.php', '/adminLogin.php',
    '/admin/index.html', '/admin/login.html',
    '/config', '/configuration', '/settings', '/setup', '/install',
    '/installer', '/installation', '/setup.php', '/install.php',
    '/config.php', '/.env', '/config.yaml', '/config.json', '/config.ini',
    '/web.config', '/appsettings.json', '/wp-config.php',
    '/backup', '/backups', '/bak', '/tmp', '/temp', '/old',
    '/.git', '/.svn', '/.hg', '/backup.sql', '/backup.zip',
    '/dump', '/dumps', '/sql-dump', '/database.sql', '/dump.sql',
    '/debug', '/phpinfo', '/test.php', '/info.php',
    '/server-status', '/server-info', '/debug.log', '/error.log',
    '/debug.php', '/trace',
])

MEDIUM_RISK_PATHS = frozenset([
    '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/rest', '/soap',
    '/api/token', '/api/login', '/api/auth', '/api/admin', '/api/users',
    '/webhook', '/swagger', '/swagger-ui', '/openapi', '/redoc', '/api-docs',
    '/wordpress', '/wp-admin', '/wp-login.php', '/wp-content', '/wp-json',
    '/joomla', '/drupal', '/cms', '/magento',
    '/auth', '/oauth', '/oauth2', '/sso', '/jwt', '/session', '/token',
    '/signup', '/register', '/reset-password', '/forgot-password', '/2fa', '/mfa',
    '/monitor', '/monitoring', '/metrics', '/stats', '/analytics',
    '/grafana', '/prometheus', '/kibana', '/health', '/healthcheck',
    '/index.php.bak', '/index.php.old', '/config.php.bak', '/config.php.old',
    '/.env.old', '/.env.bak', '/web.config.old', '/web.config.bak',
])

LOW_RISK_PATHS = frozenset([
    '/www', '/static', '/assets', '/cdn', '/blog', '/news', '/shop', '/store',
    '/favicon.ico', '/rss', '/feed', '/search', '/about', '/contact',
    '/privacy', '/terms', '/legal', '/careers', '/jobs', '/faq', '/help',
    '/support', '/docs', '/documentation', '/pricing', '/downloads',
    '/uploads', '/media', '/public',
    '/.aws', '/.azure', '/.dockerenv', '/docker-compose.yml',
    '/Jenkinsfile', '/.circleci', '/.travis.yml', '/.gitlab-ci.yml',
    '/.DS_Store', '/.idea', '/.vscode',
])


# ---------------------------------------------------------------------------
# Technology Points (unchanged)
# ---------------------------------------------------------------------------
TECHNOLOGY_POINTS = {
    'apache': 7, 'nginx': 5, 'iis': 8, 'lighttpd': 4, 'caddy': 3,
    'tomcat': 8, 'jetty': 6, 'weblogic': 9, 'websphere': 8,
    'glassfish': 7, 'jboss': 8,
    'php': 9, 'python': 4, 'perl': 6, 'ruby': 5, 'java': 6,
    'asp.net': 8, 'node.js': 7, 'go': 3, 'rust': 2, 'coldfusion': 9,
    'wordpress': 10, 'joomla': 9, 'drupal': 9, 'magento': 10,
    'prestashop': 8, 'opencart': 8, 'shopify': 5, 'ghost': 5,
    'mysql': 8, 'mariadb': 7, 'postgresql': 6, 'mongodb': 9,
    'redis': 7, 'elasticsearch': 9, 'couchdb': 7, 'cassandra': 6,
    'oracle': 7, 'sql server': 8,
    'django': 6, 'flask': 5, 'ruby on rails': 8, 'laravel': 9,
    'symfony': 8, 'express': 7, 'spring': 7, 'struts': 9,
    'jquery': 5, 'react': 6, 'angular': 7, 'vue.js': 5, 'bootstrap': 3,
    'docker': 7, 'kubernetes': 7, 'openshift': 6,
    'oauth': 5, 'ldap': 6, 'active directory': 8,
    'ftp': 8, 'telnet': 10, 'ssh': 4, 'rdp': 9, 'vpn': 7,
}




# ---------------------------------------------------------------------------
# Core Analysis Functions
# ---------------------------------------------------------------------------
def load_subdomains(file_path):
    subdomains = set()
    try:
        with open(file_path, "r") as f:
            for line in f:
                s = line.strip()
                if s:
                    subdomains.add(s)
    except FileNotFoundError:
        cprint(f"[ERROR] Input file not found: {file_path}", Fore.RED if HAS_COLOR else None)
        sys.exit(1)
    return subdomains


def analyze_subdomain_name(subdomain):
    points = 0
    matched = []
    sub_part = tldextract.extract(subdomain).subdomain.lower()
    tokens = set(re.split(r'\W+', sub_part))

    for kw in SUBDOMAIN_KEYWORDS:
        if kw in tokens:
            matched.append(kw)
            points += 5 if kw in HIGH_CRIT_KEYWORDS else 3

    return points, matched


def fetch_historical_urls(subdomain, timeout=10, verbose=False):
    """Fetch historical URLs via gau. Returns empty list on failure (never exits)."""
    if verbose:
        cprint(f"  [gau] Fetching URLs for {subdomain}...", Fore.CYAN if HAS_COLOR else None)
    try:
        result = subprocess.run(
            ["gau", subdomain],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=120,
        )
        urls = list({u for u in result.stdout.strip().split("\n") if u})
        if verbose:
            cprint(f"  [gau] {len(urls)} unique URLs for {subdomain}", Fore.CYAN if HAS_COLOR else None)
        return urls
    except FileNotFoundError:
        logging.warning("gau not found in PATH — skipping URL fetching")
        if verbose:
            cprint("  [gau] Tool not found in PATH — skipping", Fore.YELLOW if HAS_COLOR else None)
        return []
    except subprocess.TimeoutExpired:
        logging.warning(f"gau timed out for {subdomain}")
        return []
    except Exception as e:
        logging.error(f"gau error for {subdomain}: {e}")
        return []


def analyze_urls(urls, verbose=False):
    points = 0
    matched = set()

    unique_paths = set()
    for url in urls:
        path = re.sub(r'\?.*$', '', url)
        path = re.sub(r'https?://[^/]+', '', path).lower()
        if path:
            unique_paths.add(path)

    for p in unique_paths:
        if p in HIGH_RISK_PATHS:
            matched.add(p); points += 7
        elif p in MEDIUM_RISK_PATHS:
            matched.add(p); points += 5
        elif p in LOW_RISK_PATHS:
            matched.add(p); points += 2

    return points, sorted(matched)




def get_http_status(subdomain, timeout=10):
    """Return HTTP status code and whether HTTPS works."""
    info = {"http_status": None, "https": False, "redirect_to": None}
    for scheme in ("https", "http"):
        try:
            resp = requests.head(f"{scheme}://{subdomain}", timeout=timeout, allow_redirects=False)
            info["http_status"] = resp.status_code
            if scheme == "https":
                info["https"] = True
            if 300 <= resp.status_code < 400:
                info["redirect_to"] = resp.headers.get("Location", "")
            return info
        except Exception:
            continue
    return info


def get_first_certificate_timestamp(subdomain, timeout=10, verbose=False):
    if verbose:
        cprint(f"  [crt.sh] Fetching certs for {subdomain}...", Fore.CYAN if HAS_COLOR else None)
    try:
        url = f"https://crt.sh/?q={subdomain}&output=json"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            if data:
                earliest = None
                for cert in data:
                    nb = cert.get("not_before", "")
                    # Handle both with and without milliseconds
                    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
                        try:
                            dt = datetime.strptime(nb, fmt)
                            if earliest is None or dt < earliest:
                                earliest = dt
                            break
                        except ValueError:
                            continue
                if earliest:
                    age_years = (datetime.now() - earliest).days // 365
                    return age_years, earliest.date()
        return None, None
    except Exception as e:
        logging.error(f"crt.sh error for {subdomain}: {e}")
        return None, None


def get_wayback_first_capture(subdomain, timeout=10, verbose=False):
    if verbose:
        cprint(f"  [wayback] Fetching archive data for {subdomain}...", Fore.CYAN if HAS_COLOR else None)
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={subdomain}&output=json&limit=1&filter=statuscode:200&from=1996"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:
                ts = data[1][1]
                dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
                age_years = (datetime.now() - dt).days // 365
                return age_years, dt.date()
        return None, None
    except Exception as e:
        logging.error(f"Wayback error for {subdomain}: {e}")
        return None, None


def get_subdomain_age(subdomain, timeout=10, verbose=False):
    age_crt, date_crt = get_first_certificate_timestamp(subdomain, timeout, verbose)
    age_wb, date_wb = get_wayback_first_capture(subdomain, timeout, verbose)

    candidates = []
    if age_crt is not None:
        candidates.append((age_crt, date_crt, "crt.sh"))
    if age_wb is not None:
        candidates.append((age_wb, date_wb, "Wayback Machine"))

    if candidates:
        return max(candidates, key=lambda x: x[0])
    return None, None, None


def analyze_technologies(wappalyzer, subdomain, timeout=10, verbose=False):
    """Detect technologies, trying HTTPS first then HTTP."""
    if verbose:
        cprint(f"  [wappalyzer] Detecting tech for {subdomain}...", Fore.CYAN if HAS_COLOR else None)
    tech_points = 0
    technologies = set()

    for scheme in ("https", "http"):
        try:
            webpage = WebPage.new_from_url(f"{scheme}://{subdomain}", timeout=timeout)
            detected = wappalyzer.analyze_with_versions_and_categories(webpage)
            for tech in detected:
                technologies.add(tech)
                pts = TECHNOLOGY_POINTS.get(tech.lower(), 2)
                tech_points += pts
            break  # success — stop trying
        except Exception:
            continue

    return tech_points, sorted(technologies)


# ---------------------------------------------------------------------------
# Risk Classification
# ---------------------------------------------------------------------------
def classify_risk(score):
    if score >= 50:
        return "CRITICAL"
    elif score >= 30:
        return "HIGH"
    elif score >= 15:
        return "MEDIUM"
    elif score >= 5:
        return "LOW"
    return "INFO"


def risk_color(level):
    if not HAS_COLOR:
        return None
    return {
        "CRITICAL": Fore.RED,
        "HIGH": Fore.LIGHTRED_EX,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.GREEN,
        "INFO": Fore.WHITE,
    }.get(level, None)


# ---------------------------------------------------------------------------
# Per-Subdomain Analysis (runs inside a thread)
# ---------------------------------------------------------------------------
def analyze_subdomain(subdomain, wappalyzer=None, timeout=10, skip_gau=False, skip_wappalyzer=False, verbose=False):
    total = 0
    result = {
        "subdomain": subdomain,
        "total_points": 0,
        "risk_level": "INFO",
        "matched_keywords": [],
        "matched_paths": [],
        "technologies": [],
        "http_info": {},
        "subdomain_age": "Unknown",
        "breakdown": {},
    }

    if verbose:
        cprint(f"\n--- Analyzing {subdomain} ---", Fore.MAGENTA if HAS_COLOR else None)

    # 1. Subdomain name analysis
    kw_pts, kw_list = analyze_subdomain_name(subdomain)
    total += kw_pts
    result["matched_keywords"] = kw_list
    result["breakdown"]["keywords"] = kw_pts

    # 2. Historical URLs via gau
    if not skip_gau:
        urls = fetch_historical_urls(subdomain, timeout=timeout, verbose=verbose)
        if urls:
            url_pts, paths = analyze_urls(urls, verbose=verbose)
            total += url_pts
            result["matched_paths"] = paths
            result["breakdown"]["paths"] = url_pts
    else:
        result["breakdown"]["paths"] = 0

    # 3. Technology detection
    if not skip_wappalyzer and wappalyzer and HAS_WAPPALYZER:
        tech_pts, techs = analyze_technologies(wappalyzer, subdomain, timeout=timeout, verbose=verbose)
        total += tech_pts
        result["technologies"] = techs
        result["breakdown"]["technologies"] = tech_pts
    else:
        result["breakdown"]["technologies"] = 0

    # 4. HTTP info
    result["http_info"] = get_http_status(subdomain, timeout=timeout)

    # 5. Subdomain age
    age_years, date_used, method = get_subdomain_age(subdomain, timeout=timeout, verbose=verbose)
    if age_years is not None:
        if age_years >= 10:
            age_pts = 10
        elif age_years >= 5:
            age_pts = 5
        else:
            age_pts = 2
        total += age_pts
        result["subdomain_age"] = f"{age_years} years (since {date_used}, via {method})"
        result["breakdown"]["age"] = age_pts
    else:
        result["breakdown"]["age"] = 0

    result["total_points"] = total
    result["risk_level"] = classify_risk(total)
    return result


# ---------------------------------------------------------------------------
# Report Writers
# ---------------------------------------------------------------------------
def write_txt_report(results, path):
    with open(path, "w") as f:
        f.write(f"Subdomain Analysis Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        for r in results:
            f.write(f"Subdomain    : {r['subdomain']}\n")
            f.write(f"Risk Level   : {r['risk_level']}\n")
            f.write(f"Total Score  : {r['total_points']}\n")
            f.write(f"Keywords     : {', '.join(r['matched_keywords']) or 'None'}\n")
            f.write(f"Risky Paths  : {', '.join(r['matched_paths']) or 'None'}\n")
            f.write(f"Technologies : {', '.join(r['technologies']) or 'None'}\n")

            http = r.get("http_info", {})
            f.write(f"HTTP Status  : {http.get('http_status', 'N/A')}  HTTPS: {http.get('https', False)}\n")
            f.write(f"Subdomain Age: {r['subdomain_age']}\n")
            f.write(f"Score Brkdown: {r.get('breakdown', {})}\n")
            f.write("-" * 70 + "\n")


def write_json_report(results, path):
    with open(path, "w") as f:
        json.dump({"generated": datetime.now().isoformat(), "results": results}, f, indent=2, default=str)


def write_csv_report(results, path):
    if not results:
        return
    with open(path, "w", newline="") as f:
        cols = ["subdomain", "risk_level", "total_points", "matched_keywords",
                "matched_paths", "technologies", "subdomain_age"]
        writer = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            row = dict(r)
            for k in ("matched_keywords", "matched_paths", "technologies"):
                row[k] = "; ".join(row.get(k, []))
            writer.writerow(row)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = parse_arguments()
    banner()
    setup_logging(args.verbose)

    subdomains = load_subdomains(args.input)
    total = len(subdomains)
    cprint(f"[*] Loaded {total} subdomains from {args.input}", Fore.GREEN if HAS_COLOR else None)

    # Initialize Wappalyzer ONCE
    wappalyzer = None
    if HAS_WAPPALYZER and not args.no_wappalyzer:
        try:
            wappalyzer = Wappalyzer.latest()
            cprint("[*] Wappalyzer initialized", Fore.GREEN if HAS_COLOR else None)
        except Exception as e:
            cprint(f"[!] Wappalyzer init failed: {e}", Fore.YELLOW if HAS_COLOR else None)

    results = []
    from concurrent.futures import ThreadPoolExecutor, as_completed

    cprint(f"[*] Starting analysis with {args.threads} threads...\n", Fore.GREEN if HAS_COLOR else None)

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(
                analyze_subdomain, sub,
                wappalyzer=wappalyzer,
                timeout=args.timeout,
                skip_gau=args.no_gau,
                skip_wappalyzer=args.no_wappalyzer,
                verbose=args.verbose,
            ): sub for sub in subdomains
        }
        for idx, future in enumerate(as_completed(futures), 1):
            sub = futures[future]
            try:
                res = future.result()
                results.append(res)
                lvl = res["risk_level"]
                cprint(
                    f"[{idx}/{total}] {sub}  →  Score: {res['total_points']}  Risk: {lvl}",
                    risk_color(lvl),
                )
            except Exception as e:
                logging.error(f"Error processing {sub}: {e}")
                cprint(f"[{idx}/{total}] {sub}  →  ERROR: {e}", Fore.RED if HAS_COLOR else None)

    # Sort by score descending
    results.sort(key=lambda x: x["total_points"], reverse=True)

    # Write report
    writers = {"txt": write_txt_report, "json": write_json_report, "csv": write_csv_report}
    writers[args.format](results, args.output)
    cprint(f"\n[✓] Report saved to {args.output} ({args.format})", Fore.GREEN if HAS_COLOR else None)

    # Summary
    risk_counts = defaultdict(int)
    for r in results:
        risk_counts[r["risk_level"]] += 1

    cprint("\n=== Summary ===", Fore.CYAN if HAS_COLOR else None)
    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if risk_counts[lvl]:
            cprint(f"  {lvl}: {risk_counts[lvl]}", risk_color(lvl))
    cprint(f"  Total: {total}\n")


if __name__ == "__main__":
    main()
