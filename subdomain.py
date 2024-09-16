#!/usr/bin/env python3

import argparse
import re
import warnings
import tldextract
import subprocess
import whois
from datetime import datetime
import logging
from collections import defaultdict
from Wappalyzer import Wappalyzer, WebPage

from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress specific UserWarnings from Wappalyzer
warnings.filterwarnings(
    "ignore",
    message=".*unbalanced parenthesis at position 119.*",
    category=UserWarning,
    module="Wappalyzer"
)

# Highly focused list of subdomain keywords for optimal reconnaissance
SUBDOMAIN_KEYWORDS = [
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

    # Continuous Integration and Deployment
    'ci', 'cd', 'build', 'deploy', 'jenkins', 'gitlab', 'github',
    'bitbucket', 'circleci', 'travis', 'teamcity', 'drone', 'artifactory',

    # Business and Enterprise Applications
    'crm', 'erp', 'sharepoint', 'jira', 'confluence', 'zendesk', 'sap',

    # Finance and Payment Systems
    'payment', 'billing', 'invoice', 'checkout', 'pay', 'banking',
    'transaction', 'wallet', 'merchant', 'ecommerce',

    # Human Resources and Employee Services
    'hr', 'employee', 'staff', 'payroll', 'jobs', 'careers', 'talent',
    'recruitment', 'onboarding', 'people', 'benefits',

    # Legal and Compliance
    'legal', 'compliance', 'audit', 'policy', 'gdpr', 'hipaa', 'ccpa',

    # Customer Support and Services
    'support', 'helpdesk', 'servicedesk', 'ticket', 'zendesk', 'jira',

    # Security and Compliance
    'security', 'auth', 'authorize', 'authorization', 'token', 'jwt',
    'password', 'passwd', 'vault', 'secret', 'ssh', 'ssl', 'tls', 'encryption',

    # Miscellaneous High-Value Keywords
    'www', 'static', 'assets', 'cdn', 'blog', 'news', 'shop', 'store',
    'api', 'mobile', 'm', 'test', 'dev', 'beta', 'prod', 'secure', 'private',
]

# High-Risk Paths
HIGH_RISK_PATHS = set([
    # Administrative and Login Interfaces
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

    # Sensitive Configuration Files
    '/config', '/configuration', '/settings', '/setup', '/install',
    '/installer', '/installation', '/setup.php', '/install.php',
    '/config.php', '/.env', '/environment', '/config.yaml',
    '/config.json', '/config.ini', '/web.config', '/application.config',
    '/appsettings.json', '/settings.php', '/db_config',
    '/database.yml', '/db.cfg', '/config/db', '/conf', '/cfg',
    '/config.old', '/config.bak', '/config/', '/config~',
    '/localsettings.php', '/wp-config.php', '/config/database.php',
    '/connections.yml', '/config.xml', '/config.jsp', '/config.asp',
    '/dbconfig.php', '/database.ini', '/database.json',
    '/database.xml', '/settings.ini', '/settings.json',
    '/settings.xml', '/app.config', '/application.ini',
    '/application.json', '/config_backup', '/config/save',
    '/config/save/old', '/config.old.php', '/config.save.php',
    '/config_backup.php',

    # Backup, Old, Temp Files
    '/backup', '/backups', '/bak', '/tmp', '/temp', '/old',
    '/old_version', '/archive', '/archives', '/.git', '/.svn',
    '/.hg', '/backup.sql', '/backup.zip', '/oldsite', '/test',
    '/testsite', '/testdb', '/tempfiles', '/oldfiles', '/dump',
    '/dumps', '/sql-dump', '/log.bak', '/access.bak',
    '/old-admin', '/backup/admin', '/backup/config',
    '/backup/database', '/bak.zip', '/backup.tar.gz',
    '/backup_old', '/db_backup', '/database.sql', '/dump.sql',
    '/db.sql', '/db.dump', '/website.zip', '/site_backup',
    '/backup/site', '/backup/home', '/backup/www',
    '/backup/public_html', '/tmp/', '/temp/', '/logs/',
    '/logs.old', '/logs.bak', '/error.log', '/access.log',
    '/debug.log', '/data.bak', '/data.old', '/uploads.old',
    '/uploads.bak', '/uploads.zip', '/images.bak',
    '/old_site', '/site_old', '/copy', '/copy_site',
    '/backup_2021', '/backup_2022', '/backup_2023',

    # Debug and Testing Paths
    '/debug', '/debugging', '/debug-info', '/phpinfo', '/test',
    '/testing', '/testpage', '/test.php', '/info.php', '/status',
    '/status.php', '/diagnostic', '/test1', '/test2', '/testsite',
    '/dev', '/development', '/debug.asp', '/debug/config',
    '/debug/test', '/trace', '/traces', '/devinfo',
    '/devpanel', '/staging', '/stage', '/beta', '/alpha',
    '/preprod', '/qa', '/sandbox', '/server-status',
    '/server-info', '/debug.log', '/error.log',
    '/logs/debug.log', '/dev/', '/dev/test', '/test-env',
    '/env', '/environment', '/test_environment',
    '/test_env', '/beta/', '/beta/test', '/testing/',
    '/testing/site', '/new', '/newsite', '/new_site',
    '/trial', '/demo', '/demo_site', '/demo-version',
    '/trial-version', '/sample', '/samples', '/examples',
    '/example', '/debug.php'
])

# Medium-Risk Paths
MEDIUM_RISK_PATHS = set([
    # API Endpoints and Web Services
    '/api', '/api/v1', '/api/v2', '/graphql', '/rest', '/soap',
    '/services', '/service', '/api/token', '/api/login',
    '/api/register', '/api/logout', '/api/auth', '/api/data',
    '/api/private', '/api/public', '/api/admin', '/api/users',
    '/api/orders', '/rest/v1', '/soap/v1', '/rest-api', '/api/v3',
    '/webhook', '/callback', '/auth/callback', '/webhook.php',
    '/v1/graphql', '/api-docs', '/swagger', '/swagger-ui',
    '/openapi', '/redoc', '/api/help', '/api/v1/users',
    '/api/v1/accounts', '/api/v1/auth', '/api/v1/login',
    '/api/status', '/api/health', '/api/info', '/api/v1/info',
    '/api/v1/status', '/api/metrics', '/api/logs', '/api/debug',
    '/api/test', '/api/sample', '/api/example', '/api/v1/items',
    '/api/v1/products', '/api/v1/customers', '/api/v1/transactions',
    '/api/v1/payments', '/api/v1/invoices',

    # Content Management Systems (CMS)
    '/wordpress', '/wp-admin', '/wp-login.php', '/wp-content',
    '/wp-includes', '/wp-json', '/joomla', '/drupal', '/cms',
    '/magento', '/typo3', '/prestashop', '/opencart', '/store/admin',
    '/shop/admin', '/admin/cart', '/admin/orders', '/shop/cart',
    '/cms/admin', '/cms-login.php', '/cms/wp-login.php', '/umbraco',
    '/silverstripe', '/contao', '/concrete5', '/dotnetnuke',
    '/squarespace', '/ghost', '/blog/wp-admin', '/blog/wp-login.php',
    '/craft', '/cms/login', '/processwire', '/statamic',
    '/expressionengine', '/october', '/phpbb', '/vbulletin',
    '/moodle', '/liferay', '/weebly', '/shopify', '/bigcommerce',
    '/zendesk', '/helpdesk', '/kayako',

    # Web Application Files and Extensions
    '/app', '/apps', '/application', '/applications', '/webapp',
    '/webapp.php', '/plugin', '/plugins', '/plugin/install', '/addon',
    '/addons', '/module', '/modules', '/mod', '/modrewrite', '/ext',
    '/extensions', '/custom-modules', '/custom-plugins', '/themes',
    '/templates', '/site-themes', '/themes/install', '/components',
    '/assets', '/includes', '/lib', '/libraries', '/vendor',
    '/node_modules', '/gulpfile.js', '/gruntfile.js', '/composer.json',
    '/package.json', '/yarn.lock', '/build', '/builds', '/src',
    '/source', '/assets/css', '/assets/js', '/assets/images',
    '/assets/fonts', '/assets/plugins', '/themes/default',
    '/themes/classic', '/themes/basic', '/template', '/templates',
    '/skin', '/skins', '/widgets', '/blocks', '/partials',
    '/fragments', '/snippets', '/scripts', '/scripts/', '/javascripts',
    '/stylesheets', '/styles', '/css',

    # Authentication and Authorization
    '/auth', '/authentication', '/authorize', '/session', '/sessions',
    '/token', '/tokens', '/oauth', '/oauth2', '/access', '/jwt',
    '/sso', '/signup', '/register', '/signin', '/user/signup',
    '/account/login', '/account/logout', '/account/register',
    '/reset-password', '/forgot-password', '/user/password/reset',
    '/user/password/forgot', '/verify', '/validate',
    '/activation', '/activation-link', '/auth.php',
    '/authenticator', '/login.action', '/login1',
    '/login_admin', '/user/signin', '/signin.php',
    '/members', '/member/login', '/user/login.php',
    '/password_reset', '/forgotpassword', '/forgot_pwd',
    '/change_password', '/password/change', '/user/forgot',
    '/account/forgot', '/user/reset', '/account/reset',
    '/validate', '/verify_email', '/email/verify',
    '/confirm', '/confirmation', '/2fa', '/mfa', '/security',
    '/security/login', '/auth/login', '/auth/signin',
    '/account/signin',

    # Monitoring, Metrics, and Analytics
    '/monitor', '/monitoring', '/metrics', '/stats', '/statistics',
    '/analytics', '/report', '/reports', '/uptime', '/incident',
    '/incidents', '/status-report', '/status-page', '/monitor/status',
    '/logs/stats', '/error/stats', '/grafana', '/prometheus',
    '/dashboard', '/kibana', '/logs', '/elk', '/zabbix',
    '/newrelic', '/datadog', '/appmetrics', '/awstats', '/piwik',
    '/metrics/', '/analytics/', '/googleanalytics', '/matomo',
    '/logviewer', '/logs/view', '/logs/error', '/logs/access',
    '/system/logs', '/system/status', '/health', '/healthcheck',
    '/diagnostics', '/system/health', '/admin/logs',

    # Common File Extensions and Backup Files
    '/index.php~', '/index.php.bak', '/index.php.old',
    '/index.php.save', '/index.php.swp', '/index.html~',
    '/index.html.bak', '/index.html.old', '/index.html.save',
    '/index.html.swp', '/index.asp', '/index.aspx',
    '/default.aspx', '/home.aspx', '/home.php', '/home.html',
    '/config.php~', '/config.php.bak', '/config.php.old',
    '/config.php.save', '/config.php.swp', '/settings.py',
    '/settings.pyc', '/settings.pyo', '/settings.old',
    '/settings.bak', '/.env.old', '/.env.bak',
    '/.env.save', '/web.config.old', '/web.config.bak',
    '/web.config.save', '/database.yml~', '/database.yml.bak',
    '/database.yml.old', '/database.yml.save'
])

# Low-Risk Paths
LOW_RISK_PATHS = set([
    # Static and Public Assets
    '/www', '/static', '/assets', '/cdn', '/blog', '/news', '/shop',
    '/store', '/favicon.ico', '/rss', '/feed', '/atom', '/subscribe',
    '/unsubscribe', '/newsletter', '/data', '/dataset', '/backup_files',
    '/backup_db', '/old_version', '/search', '/autocomplete',
    '/autosuggest', '/suggestions', '/query', '/query.php',
    '/get-data', '/getfile', '/fetchfile', '/downloadfile',
    '/customer-support', '/helpdesk', '/support-center', '/tickets',
    '/issues', '/track', '/tracking', '/alerts', '/alert',
    '/notification', '/notifications', '/error-log', '/log/error',
    '/logs/errors', '/logs/access', '/system/info', '/about',
    '/contact', '/contact-us', '/contactus', '/about-us', '/privacy',
    '/terms', '/terms-of-service', '/legal', '/careers', '/jobs',
    '/blog', '/news', '/events', '/press', '/faq', '/help',
    '/support', '/docs', '/documentation', '/status', '/pricing',
    '/partners', '/api-keys', '/keys', '/license', '/licenses',
    '/downloads', '/download', '/uploads', '/media', '/static',
    '/public', '/private', '/tmp', '/temp', '/cache', '/config',
    '/configurations', '/setup', '/install', '/installer',
    '/install.php', '/test', '/tests', '/example', '/examples',
    '/sample', '/samples', '/demo', '/home', '/main', '/default',
    '/index', '/welcome', '/old', '/backup', '/core', '/include',
    '/includes', '/inc', '/system', '/sys', '/app', '/apps',
    '/cgi-bin', '/cgi', '/scripts', '/script', '/bin', '/utils',
    '/tools', '/admin_tools', '/webmail', '/email', '/mail',
    '/user_mail', '/newsletter_signup',

    # Cloud and Storage Paths
    '/.aws', '/.azure', '/.env.production', '/.env.development',
    '/.env.local', '/.dockerenv', '/docker-compose.yml',
    '/Jenkinsfile', '/jenkins', '/.circleci', '/.travis.yml',
    '/.gitlab-ci.yml', '/.bzr', '/.bzr/branch/',
    '/.DS_Store', '/.svn/entries', '/.idea', '/.vscode',
    '/.project', '/.editorconfig', '/azure-pipelines.yml',
    '/bitbucket-pipelines.yml', '/appveyor.yml', '/kubernetes.yml',
    '/helm', '/charts', '/k8s', '/kubernetes', '/docker',
    '/dockerfile', '/docker-compose', '/compose', '/terraform',
    '/ansible', '/puppet', '/chef', '/salt', '/cloudformation',
    '/s3', '/s3bucket', '/storage', '/bucket', '/gcp',
    '/google-cloud', '/aws', '/lambda', '/functions',

    # Version Control and Repository Paths
    '/.git/', '/.git/config', '/.git/logs/', '/.git/refs/',
    '/.svn/', '/.hg/', '/.bzr/', '/.cvs/',
    '/.git/hooks/post-update.sample', '/.git/index',
    '/.git/objects/', '/.git/HEAD', '/.git/COMMIT_EDITMSG',
    '/.git/logs/HEAD', '/.git/FETCH_HEAD', '/.git/ORIG_HEAD',
    '/.git/description', '/.git/info/', '/.git/packed-refs',
    '/.git/refs/heads/', '/.git/refs/remotes/',
    '/.git/refs/tags/', '/.svn/wc.db', '/.svn/all-wcprops',
    '/.svn/entries', '/.svn/prop-base/', '/.svn/props/',
    '/.svn/text-base/', '/.svn/tmp/', '/.hg/store/',
    '/.hg/store/data/', '/.hg/store/00changelog.i',
    '/.hg/dirstate', '/.bzr/branch/', '/.bzr/checkout/',
    '/.bzr/repository/', '/.bzr/checkout/dirstate'
])

# Updated Comprehensive mapping of technologies to points based on potential vulnerabilities

TECHNOLOGY_POINTS = {

    # Web Servers
    'apache': 7,        # Frequent misconfigurations, many CVEs
    'nginx': 5,         # Secure, but misconfigurations occur
    'iis': 8,           # Often misconfigured, several vulnerabilities
    'lighttpd': 4,      # Less common, but potential for issues
    'caddy': 3,         # Secure by design, fewer vulnerabilities
    'tomcat': 8,        # Prone to misconfigurations, CVEs reported
    'jetty': 6,         # Security flaws, moderate use in production
    'weblogic': 9,      # High-profile vulnerabilities (e.g., RCEs)
    'websphere': 8,     # Older systems, prone to critical vulnerabilities
    'glassfish': 7,     # History of serious security issues
    'jboss': 8,         # Known for high-risk vulnerabilities, RCEs

    # Programming Languages
    'php': 9,           # Frequent vulnerabilities, improper input validation
    'python': 4,        # Relatively secure, but common misconfigurations
    'perl': 6,          # Old, but still used, security flaws exist
    'ruby': 5,          # Secure, but certain frameworks like Rails have issues
    'java': 6,          # Secure, but frameworks may introduce vulnerabilities
    'asp.net': 8,       # Historically prone to injection attacks
    'node.js': 7,       # Secure by default, but many vulnerable libraries
    'go': 3,            # Secure by design, low risk
    'rust': 2,          # Secure, with memory safety guarantees
    'coldfusion': 9,    # Known for numerous critical vulnerabilities
    'lua': 4,           # Niche, but some vulnerabilities exist
    'elixir': 3,        # Secure and less common, fewer vulnerabilities
    'clojure': 2,       # Secure by nature, low risk

    # Content Management Systems (CMS)
    'wordpress': 10,    # Constantly exploited, huge attack surface
    'joomla': 9,        # Frequently exploited, many vulnerabilities
    'drupal': 9,        # History of high-profile vulnerabilities (e.g., "Drupalgeddon")
    'magento': 10,      # Often targeted for e-commerce attacks
    'typo3': 7,         # Less common but prone to issues
    'prestashop': 8,    # Many vulnerabilities related to e-commerce
    'opencart': 8,      # Commonly targeted in e-commerce breaches
    'shopify': 5,       # Generally secure, but attacks on plugins
    'wix': 4,           # Secure, fewer vulnerabilities
    'weebly': 4,        # Secure, few issues reported
    'squarespace': 4,   # Secure, few issues reported
    'ghost': 5,         # Secure, but some vulnerabilities
    'blogger': 3,       # Google-backed, few security issues
    'tumblr': 3,        # Few reported issues

    # Databases
    'mysql': 8,         # Frequent vulnerabilities, improper configurations
    'mariadb': 7,       # Similar to MySQL, but fewer vulnerabilities
    'postgresql': 6,    # Secure, but some vulnerabilities exist
    'mongodb': 9,       # Many incidents due to misconfigurations
    'redis': 7,         # Often misconfigured, exposed to the internet
    'elasticsearch': 9, # Commonly misconfigured, exposed to RCE
    'couchdb': 7,       # Often misconfigured, vulnerable to attacks
    'cassandra': 6,     # Secure by default, but misconfigurations exist
    'oracle': 7,        # Secure but older versions prone to serious flaws
    'sql server': 8,    # Targeted often, critical vulnerabilities exist
    'db2': 5,           # Relatively secure, but fewer critical flaws
    'hbase': 6,         # Secure, but certain vulnerabilities reported

    # Application Frameworks
    'django': 6,        # Secure but some critical vulnerabilities
    'flask': 5,         # Secure, but custom configurations may introduce issues
    'ruby on rails': 8, # History of high-profile vulnerabilities (e.g., mass assignment)
    'laravel': 9,       # PHP-based, prone to many security flaws
    'symfony': 8,       # Secure, but vulnerabilities have been found
    'express': 7,       # Node.js framework, but vulnerable modules are common
    'spring': 7,        # Secure, but several vulnerabilities have been found
    'struts': 9,        # Known for significant vulnerabilities (e.g., Equifax breach)
    'codeigniter': 7,   # PHP-based, moderate security issues
    'cakephp': 7,       # Similar to CodeIgniter, some vulnerabilities
    'zend framework': 7,# PHP-based, secure, but several CVEs
    'asp.net mvc': 8,   # Secure, but known vulnerabilities

    # JavaScript Libraries and Frameworks
    'jquery': 5,        # Historically exploited for XSS, outdated libraries
    'react': 6,         # Secure, but dependent on library versions
    'angular': 7,       # Secure, but can introduce XSS vulnerabilities
    'vue.js': 5,        # Secure, fewer vulnerabilities
    'ember.js': 5,      # Secure but prone to misconfigurations
    'backbone.js': 4,   # Outdated, but some vulnerabilities
    'dojo': 4,          # Older, fewer vulnerabilities
    'extjs': 5,         # Secure, but historically vulnerable libraries
    'bootstrap': 3,     # Secure, minimal vulnerabilities
    'semantic ui': 3,   # Secure, minimal issues

    # Operating Systems
    'windows': 7,       # Historically vulnerable to many critical flaws
    'linux': 4,         # Secure but misconfigurations occur
    'ubuntu': 4,        # Relatively secure, but some flaws reported
    'centos': 4,        # Secure, minimal issues
    'red hat': 4,       # Secure, widely used in enterprises
    'debian': 4,        # Secure, but historical vulnerabilities
    'freebsd': 3,       # Secure, fewer vulnerabilities
    'openbsd': 3,       # Known for its security, low-risk

    # Containers and Orchestration
    'docker': 7,        # Misconfigurations, privilege escalation risks
    'kubernetes': 7,    # Security incidents due to misconfigurations
    'openshift': 6,     # Similar to Kubernetes, with potential risks
    'mesos': 5,         # Secure, but misconfigurations
    'rancher': 5,       # Secure, moderate issues reported
    'nomad': 4,         # Secure, fewer vulnerabilities reported

    # Authentication and Security
    'oauth': 5,         # Secure, but prone to misimplementations
    'saml': 5,          # Secure, but implementation flaws occur
    'ldap': 6,          # Common misconfigurations and injection attacks
    'active directory': 8, # Frequently targeted in attacks
    'okta': 5,          # Secure, but some vulnerabilities reported
    'auth0': 5,         # Secure, but dependent on implementation
    'shibboleth': 6,    # Secure but certain flaws
    'keycloak': 6,      # Secure, but prone to misconfigurations
    'forgerock': 6,     # Secure, but some vulnerabilities reported

    # Miscellaneous
    'ftp': 8,           # Known for security flaws, not encrypted
    'sftp': 4,          # Secure alternative to FTP
    'telnet': 10,       # Highly insecure, deprecated
    'ssh': 4,           # Secure by design, but vulnerable to misconfigurations
    'rdp': 9,           # Frequent target for RCE vulnerabilities
    'vpn': 7,           # Secure, but often targeted in breaches
    'ngrok': 6,         # Often misused for tunneling attacks
}

def parse_arguments():
    parser = argparse.ArgumentParser(description='Subdomain Analyzer and Scoring System')
    parser.add_argument('-i', '--input', required=True, help='Input file with subdomains (one per line)')
    parser.add_argument('-o', '--output', required=True, help='Output report file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    return parser.parse_args()

def setup_logging(verbose):
    """
    Configure logging settings.
    If verbose is True, log messages will also be printed to the console.
    """
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Remove any existing handlers
    logger.handlers = []

    # File handler for logging to a file
    file_handler = logging.FileHandler('subdomain_analyzer.log')
    file_handler.setLevel(logging.INFO)

    # Formatter for log messages
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    if verbose:
        # Stream handler for logging to the console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

def load_subdomains(file_path):
    subdomains = set()
    try:
        with open(file_path, 'r') as file:
            for line in file:
                subdomain = line.strip()
                if subdomain:
                    subdomains.add(subdomain)
    except FileNotFoundError:
        logging.error(f"Input file not found: {file_path}")
        print(f"Error: Input file not found: {file_path}")
        exit(1)
    return subdomains

def analyze_subdomain_name(subdomain):
    points = 0
    matched_keywords = []
    subdomain_part = tldextract.extract(subdomain).subdomain.lower()
    
    # Split the subdomain part into tokens based on non-alphanumeric characters
    tokens = re.split(r'\W+', subdomain_part)
    
    for keyword in SUBDOMAIN_KEYWORDS:
        if keyword in tokens:
            matched_keywords.append(keyword)
            if keyword in {'admin', 'administrator', 'root', 'backend', 'db', 'database', 'secure', 'server', 'internal',
                          'login', 'auth', 'sysadmin', 'portal', 'api', 'dev', 'test', 'staging', 'qa', 'vpn', 'mail',
                          'beta', 'preprod', 'prod', 'production', 'dashboard', 'controlpanel', 'manage', 'management', 
                          'oauth', 'user', 'accounts', 'profile', 'backup', 'archive', 'monitor', 'status', 'dns', 
                          'vpn', 'proxy', 'gateway', 'firewall'}:
                points += 5  # High criticality
            else:
                points += 3  # Medium criticality
    return points, matched_keywords

def fetch_historical_urls(subdomain, verbose=False):
    """
    Fetch historical URLs for a subdomain using the `gau` tool.
    Requires `gau` to be installed and accessible in the system's PATH.
    """
    if verbose:
        print(f"Fetching URLs for {subdomain} using `gau`...")
    try:
        # Execute the gau command for the subdomain
        result = subprocess.run(
            ['gau', subdomain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        urls = result.stdout.strip().split('\n') if result.stdout.strip() else []
        # Remove any empty strings and duplicates from the list
        urls = list(set([url for url in urls if url]))
        if verbose:
            print(f"Fetched {len(urls)} unique URLs for {subdomain}.")
        return urls
    except subprocess.CalledProcessError as e:
        logging.error(f"Error fetching URLs for {subdomain}: {e.stderr.strip()}")
        if verbose:
            print(f"Error fetching URLs for {subdomain}: {e.stderr.strip()}")
        return []
    except FileNotFoundError:
        logging.error("'gau' tool is not installed or not found in PATH.")
        print("Error: 'gau' tool is not installed or not found in PATH.")
        print("Please install 'gau' by following the instructions at https://github.com/lc/gau")
        exit(1)

def analyze_urls(urls, verbose=False):
    points = 0
    matched_paths = set()

    # Extract unique paths
    unique_paths = set()
    for url in urls:
        parsed_path = re.sub(r'\?.*$', '', url)  # Remove query parameters
        parsed_path = re.sub(r'http[s]?://[^/]+', '', parsed_path)  # Remove domain
        parsed_path = parsed_path.lower()
        unique_paths.add(parsed_path)

    # Iterate through unique paths
    for parsed_path in unique_paths:
        if parsed_path in HIGH_RISK_PATHS:
            matched_paths.add(parsed_path)
            points += 7  # High-risk path
            path_points = 7
            risk_level = "High"
        elif parsed_path in MEDIUM_RISK_PATHS:
            matched_paths.add(parsed_path)
            points += 5  # Medium-risk path
            path_points = 5
            risk_level = "Medium"
        elif parsed_path in LOW_RISK_PATHS:
            matched_paths.add(parsed_path)
            points += 2  # Low-risk path
            path_points = 2
            risk_level = "Low"
        else:
            continue  # Path not categorized; no points

        if verbose:
            print(f"Matched path: {parsed_path} ({risk_level} Risk) (+{path_points} points)")

    return points, list(matched_paths)

def get_domain_age(subdomain, verbose=False):
    """
    Fetch the domain age in years using WHOIS data.
    Returns the age in years as an integer. Returns None if unable to fetch.
    """
    if verbose:
        print(f"Fetching WHOIS data for {subdomain}...")
    try:
        domain_info = whois.whois(subdomain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age = datetime.now() - creation_date
            age_years = age.days // 365
            if verbose:
                print(f"Domain age for {subdomain}: {age_years} years.")
            return age_years
        else:
            logging.warning(f"Creation date not found for {subdomain}.")
            if verbose:
                print(f"Creation date not found for {subdomain}.")
            return None
    except Exception as e:
        logging.error(f"Error fetching WHOIS data for {subdomain}: {e}")
        if verbose:
            print(f"Error fetching WHOIS data for {subdomain}: {e}")
        return None

def analyze_domain_age(age_years, verbose=False):
    """
    Assign points based on the domain age.
    """
    if age_years is None:
        if verbose:
            print("Domain age unknown. Assigning 0 points.")
        return 0, "Unknown"
    if age_years >= 20:
        points = 20
    elif 15 <= age_years < 20:
        points = 15
    elif 10 <= age_years < 15:
        points = 10
    elif 5 <= age_years < 10:
        points = 5
    else:
        points = 2
    if verbose:
        print(f"Assigned {points} points based on domain age of {age_years} years.")
    return points, f"{age_years} years"

def analyze_technologies(wappalyzer, subdomain, verbose=False):
    """
    Use Wappalyzer to detect technologies used by the subdomain.
    Assign points based on the technologies detected.
    """
    if verbose:
        print(f"Detecting technologies for {subdomain} using Wappalyzer...")
    tech_points = 0
    technologies = set()
    try:
        webpage = WebPage.new_from_url(f"http://{subdomain}")
        detected_technologies = wappalyzer.analyze_with_versions_and_categories(webpage)
        for tech, info in detected_technologies.items():
            technologies.add(tech)
            points = TECHNOLOGY_POINTS.get(tech.lower(), 2)  # Default to 2 points if not specified
            tech_points += points
            if verbose:
                print(f"Detected technology '{tech}'. +{points} points")
    except Exception as e:
        logging.error(f"Error detecting technologies for {subdomain}: {e}")
        if verbose:
            print(f"Error detecting technologies for {subdomain}: {e}")
    return tech_points, list(technologies)

def analyze_subdomain(subdomain, wappalyzer, verbose=False):
    """
    Analyze a single subdomain and return the analysis result.
    """
    total_points = 0
    result = {
        'subdomain': subdomain,
        'total_points': 0,
        'matched_keywords': [],
        'matched_paths': [],
        'technologies': [],
        'domain_age': ""
    }

    if verbose:
        print(f"\n--- Analyzing {subdomain} ---")

    # Analyze subdomain name
    subdomain_points, matched_keywords = analyze_subdomain_name(subdomain)
    total_points += subdomain_points
    result['matched_keywords'] = matched_keywords
    if verbose and matched_keywords:
        print(f"Matched Keywords: {', '.join(matched_keywords)} (+{subdomain_points} points)")

    # Fetch historical URLs using gau
    urls = fetch_historical_urls(subdomain, verbose=verbose)
    if urls:
        if verbose:
            print(f"Analyzing {len(urls)} URLs for {subdomain}...")
        url_points, matched_paths = analyze_urls(urls, verbose=verbose)
        total_points += url_points
        result['matched_paths'] = matched_paths
        if verbose and matched_paths:
            print(f"Matched Paths: {', '.join(matched_paths)} (+{url_points} points)")
    else:
        if verbose:
            print(f"No URLs found or failed to fetch URLs for {subdomain}.")

    # Technology detection using Wappalyzer
    tech_points, technologies = analyze_technologies(wappalyzer, subdomain, verbose=verbose)
    total_points += tech_points
    result['technologies'] = technologies

    # Fetch and analyze domain age using WHOIS
    age_years = get_domain_age(subdomain, verbose=verbose)
    age_points, age_display = analyze_domain_age(age_years, verbose=verbose)
    total_points += age_points
    result['domain_age'] = age_display

    result['total_points'] = total_points

    return result

def main():
    args = parse_arguments()
    setup_logging(args.verbose)
    subdomains = load_subdomains(args.input)
    results = []

    # Initialize Wappalyzer once
    try:
        wappalyzer = Wappalyzer.latest()
    except Exception as e:
        logging.error(f"Error initializing Wappalyzer: {e}")
        print(f"Error initializing Wappalyzer: {e}")
        exit(1)

    total_subdomains = len(subdomains)
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_subdomain = {executor.submit(analyze_subdomain, subdomain, wappalyzer, args.verbose): subdomain for subdomain in subdomains}
        for idx, future in enumerate(as_completed(future_to_subdomain), start=1):
            subdomain = future_to_subdomain[future]
            try:
                analysis_result = future.result()
                results.append(analysis_result)
                print(f"Processed {idx}/{total_subdomains}: {subdomain}")
                logging.info(f"Processed subdomain {idx}/{total_subdomains}: {subdomain}")
            except Exception as e:
                logging.error(f"Error processing {subdomain}: {e}")
                if args.verbose:
                    print(f"Error processing {subdomain}: {e}")

    # Sort results by total points
    results.sort(key=lambda x: x['total_points'], reverse=True)

    # Generate report
    try:
        with open(args.output, 'w') as report_file:
            for res in results:
                report_file.write(f"Subdomain: {res['subdomain']}\n")
                report_file.write(f"Total Score: {res['total_points']}\n")
                report_file.write(f"Interesting Keywords Detected: {', '.join(res['matched_keywords']) if res['matched_keywords'] else 'None'}\n")
                report_file.write(f"Matched Paths: {', '.join(res['matched_paths']) if res['matched_paths'] else 'None'}\n")
                report_file.write(f"Technologies Detected: {', '.join(res['technologies']) if res['technologies'] else 'None'}\n")
                report_file.write(f"Domain Age: {res['domain_age']}\n")
                report_file.write('-' * 60 + '\n')
        print(f"\nAnalysis complete. Report saved to {args.output}")
        logging.info(f"Analysis complete. Report saved to {args.output}")
    except Exception as e:
        logging.error(f"Error writing to output file {args.output}: {e}")
        print(f"Error writing to output file {args.output}: {e}")
        exit(1)

if __name__ == "__main__":
    main()