"""Output redaction engine for fix v2.

Scrubs sensitive data from text before it leaves the machine.
Runs on every outbound message: investigation results, error output, contracts.

Each category can be independently toggled. False positives are safer than leaks.
This is a best-effort seatbelt, not a security boundary. The real protection
is the overlay sandbox hiding sensitive files from the command in the first place.
"""

import re
import os
import math

# --- Pattern categories ---

# Environment variable assignments: KEY=value
_RE_ENV_ASSIGN = re.compile(
    r'''(?:^|(?<=\s))([A-Z_][A-Z0-9_]{2,})=(["']?)(.+?)\2(?:\s|$)''',
    re.MULTILINE
)

# Known secret prefixes: API keys, tokens, passwords
_RE_TOKENS = re.compile(
    r'(?:'
    # Cloud provider keys
    r'sk-[A-Za-z0-9_-]{20,}'            # Anthropic/OpenAI
    r'|sk_live_[A-Za-z0-9]{20,}'        # Stripe secret
    r'|pk_live_[A-Za-z0-9]{20,}'        # Stripe publishable
    r'|rk_live_[A-Za-z0-9]{20,}'        # Stripe restricted
    r'|AKIA[A-Z0-9]{16}(?:/[A-Za-z0-9/+]{20,})?' # AWS access key (+ optional secret)
    r'|AIza[A-Za-z0-9_-]{35}'           # Google API key
    r'|ya29\.[A-Za-z0-9_-]+'            # Google OAuth token
    r'|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'  # SendGrid
    r'|sk-ant-[A-Za-z0-9_-]{20,}'       # Anthropic specific
    # Git forges
    r'|ghp_[A-Za-z0-9]{30,}'            # GitHub PAT
    r'|gho_[A-Za-z0-9]{30,}'            # GitHub OAuth
    r'|ghu_[A-Za-z0-9]{30,}'            # GitHub user token
    r'|ghs_[A-Za-z0-9]{30,}'            # GitHub server token
    r'|github_pat_[A-Za-z0-9_]{30,}'    # GitHub fine-grained PAT
    r'|glpat-[A-Za-z0-9_-]{20,}'        # GitLab PAT
    # Messaging/SaaS
    r'|xox[bsapr]-[A-Za-z0-9-]+'        # Slack tokens
    r'|SK[a-f0-9]{32}'                   # Twilio API key
    r'|AC[a-f0-9]{32}'                   # Twilio account SID
    r'|sq0[a-z]{3}-[A-Za-z0-9_-]{22,}'  # Square
    # Generic patterns
    r'|Bearer\s+[A-Za-z0-9._~+/=-]{20,}'  # Bearer tokens
    r'|token=[A-Za-z0-9._~+/=-]{10,}'
    r'|password=[^\s&]{3,}'
    r'|passwd=[^\s&]{3,}'
    r'|secret=[^\s&]{3,}'
    r'|api[_-]?key=[^\s&]{3,}'
    r')'
)

# Private key blocks (PEM format)
_RE_PRIVATE_KEY = re.compile(
    r'-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----'
)

# JWTs: three base64url segments separated by dots
_RE_JWT = re.compile(
    r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'
)

# Connection strings with credentials
_RE_CONN_STRING = re.compile(
    r'(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql)'
    r'://[^\s]*:[^\s]*@[^\s]+'
)

# Git remote URLs with embedded credentials
_RE_GIT_CRED_URL = re.compile(
    r'https?://[A-Za-z0-9._%-]+:[A-Za-z0-9._%-]+@[^\s]+'
)

# HTTP auth headers in output
_RE_HTTP_AUTH = re.compile(
    r'(?:Authorization|Cookie|X-API-Key|X-Auth-Token|X-Secret)'
    r'\s*[:=]\s*.+',
    re.IGNORECASE
)

# Credit card numbers (4 groups of 4 digits, with optional separators)
_RE_CREDIT_CARD = re.compile(
    r'\b(?:\d{4}[\s-]?){3}\d{4}\b'
)

# SSN
_RE_SSN = re.compile(
    r'\b\d{3}-\d{2}-\d{4}\b'
)

# Phone numbers (US and international)
_RE_PHONE = re.compile(
    r'(?:'
    r'\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}'  # international
    r'|\b\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b'                       # US format
    r')'
)

# TOTP/OTP URIs
_RE_TOTP = re.compile(
    r'otpauth://[^\s]+'
)

# Home directory paths: /home/username/ -> /home/[USER]/
_RE_HOME_PATH = None  # compiled lazily with actual username

# IPv4 addresses
_RE_IPV4 = re.compile(
    r'\b(?:'
    r'(?:10\.(?:\d{1,3}\.){2}\d{1,3})'
    r'|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})'
    r'|(?:192\.168\.\d{1,3}\.\d{1,3})'
    r'|(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r')\b'
)

# Email addresses
_RE_EMAIL = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

# High-entropy hex strings (likely keys/hashes — 64+ hex chars)
_RE_HEX_SECRET = re.compile(
    r'\b[0-9a-fA-F]{64,}\b'
)


def _get_home_re():
    """Lazily compile home path regex for current user."""
    global _RE_HOME_PATH
    if _RE_HOME_PATH is None:
        username = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
        if username:
            home = os.path.expanduser("~")
            escaped = re.escape(home)
            _RE_HOME_PATH = re.compile(escaped + r'(?=/|$|\s)')
        else:
            _RE_HOME_PATH = re.compile(r'/home/[a-z_][a-z0-9_-]*(?=/|$|\s)')
    return _RE_HOME_PATH


def _luhn_check(num_str):
    """Luhn algorithm to validate credit card numbers."""
    digits = [int(d) for d in num_str if d.isdigit()]
    if len(digits) != 16:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _entropy(s):
    """Shannon entropy of a string (bits per character)."""
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# Environment variables that are NOT sensitive
_ENV_SAFE = {
    "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE",
    "XDG_SESSION_CLASS", "XDG_SESSION_ID", "XDG_SEAT", "XDG_VTNR",
    "XDG_SEAT_PATH", "XDG_SESSION_PATH", "XDG_CONFIG_DIRS", "XDG_DATA_DIRS",
    "XDG_CURRENT_DESKTOP", "XDG_SESSION_DESKTOP", "XDG_MENU_PREFIX",
    "SHELL", "TERM", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE",
    "HOME", "USER", "LOGNAME", "PATH", "PWD", "OLDPWD", "HOSTNAME",
    "EDITOR", "VISUAL", "PAGER", "COLORTERM", "TERM_PROGRAM",
    "DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK",
    "DESKTOP_SESSION", "SESSION_MANAGER", "GDMSESSION",
    "QT_ACCESSIBILITY", "QT_IM_MODULE", "GTK_IM_MODULE",
}


# --- Scrub functions ---

def _scrub_env_vars(text):
    """Redact KEY=value assignments, preserving non-sensitive system vars."""
    def repl(m):
        key = m.group(1)
        if key in _ENV_SAFE:
            return m.group(0)
        quote = m.group(2)
        return f"{key}={quote}[REDACTED]{quote} "
    return _RE_ENV_ASSIGN.sub(repl, text)


def _scrub_tokens(text):
    """Redact known secret patterns (API keys, vendor tokens)."""
    return _RE_TOKENS.sub("[REDACTED]", text)


def _scrub_private_keys(text):
    """Redact PEM private key blocks."""
    return _RE_PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)


def _scrub_jwts(text):
    """Redact JSON Web Tokens."""
    return _RE_JWT.sub("[REDACTED_JWT]", text)


def _scrub_conn_strings(text):
    """Redact database/service connection strings with credentials."""
    return _RE_CONN_STRING.sub("[REDACTED_CONNECTION_STRING]", text)


def _scrub_git_creds(text):
    """Redact git remote URLs with embedded credentials."""
    return _RE_GIT_CRED_URL.sub("[REDACTED_URL]", text)


def _scrub_http_auth(text):
    """Redact HTTP auth headers."""
    return _RE_HTTP_AUTH.sub("[REDACTED_HEADER]", text)


def _scrub_credit_cards(text):
    """Redact credit card numbers (with Luhn validation to reduce false positives)."""
    def repl(m):
        if _luhn_check(m.group(0)):
            return "[REDACTED_CC]"
        return m.group(0)
    return _RE_CREDIT_CARD.sub(repl, text)


def _scrub_ssn(text):
    """Redact Social Security Numbers."""
    return _RE_SSN.sub("[REDACTED_SSN]", text)


def _scrub_phone(text):
    """Redact phone numbers."""
    return _RE_PHONE.sub("[REDACTED_PHONE]", text)


def _scrub_totp(text):
    """Redact TOTP/OTP URIs."""
    return _RE_TOTP.sub("[REDACTED_TOTP]", text)


def _scrub_paths(text):
    """Replace /home/username/ with /home/[USER]/."""
    home_re = _get_home_re()
    return home_re.sub("/home/[USER]", text)


def _scrub_ips(text):
    """Redact IP addresses, preserving localhost."""
    def repl(m):
        ip = m.group(0)
        if ip in ("127.0.0.1", "0.0.0.0"):
            return ip
        return "[REDACTED_IP]"
    return _RE_IPV4.sub(repl, text)


def _scrub_emails(text):
    """Redact email addresses."""
    return _RE_EMAIL.sub("[REDACTED_EMAIL]", text)


def _scrub_hex_secrets(text):
    """Redact long high-entropy hex strings (likely keys/hashes)."""
    def repl(m):
        s = m.group(0)
        if _entropy(s) > 3.5:  # random hex is ~4.0, repeated patterns are lower
            return "[REDACTED_HEX]"
        return s
    return _RE_HEX_SECRET.sub(repl, text)


# Category name -> scrub function (order matters: specific before generic)
SCRUBBERS = {
    "private_keys": _scrub_private_keys,
    "tokens": _scrub_tokens,
    "jwts": _scrub_jwts,
    "conn_strings": _scrub_conn_strings,
    "git_creds": _scrub_git_creds,
    "http_auth": _scrub_http_auth,
    "totp": _scrub_totp,
    "credit_cards": _scrub_credit_cards,
    "ssn": _scrub_ssn,
    "phone": _scrub_phone,
    "env_vars": _scrub_env_vars,
    "paths": _scrub_paths,
    "ips": _scrub_ips,
    "emails": _scrub_emails,
    "hex_secrets": _scrub_hex_secrets,
}

# All categories enabled by default
DEFAULT_CATEGORIES = set(SCRUBBERS.keys())


def scrub(text, config=None):
    """Scrub sensitive data from text.

    Args:
        text: The text to scrub.
        config: Optional dict with:
            - categories: list of category names to enable (default: all)
            - custom_patterns: list of (pattern, replacement) tuples

    Returns:
        (scrubbed_text, matched_categories) tuple.
        matched_categories is a set of category names that had matches.
    """
    if isinstance(text, bytes):
        return text, set()
    if text is None:
        return "", set()
    if not text:
        return text, set()

    if config and "categories" in config:
        categories = set(config["categories"])
    else:
        categories = DEFAULT_CATEGORIES

    matched = set()
    result = text

    for cat_name in categories:
        fn = SCRUBBERS.get(cat_name)
        if fn is None:
            continue
        scrubbed = fn(result)
        if scrubbed != result:
            matched.add(cat_name)
            result = scrubbed

    # Custom patterns
    if config and config.get("custom_patterns"):
        for pattern, replacement in config["custom_patterns"]:
            compiled = re.compile(pattern)
            new_result = compiled.sub(replacement, result)
            if new_result != result:
                matched.add("custom")
                result = new_result

    return result, matched
