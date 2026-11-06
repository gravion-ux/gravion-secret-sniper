#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SECRET SNIPER v2.2.0
Leaked credential detection & live verification.

Author   : Priyanshu Kumar Thakur (@pkt_143)
Alias    : Gravion
Telegram : @pkt_143
GitHub   : https://github.com/gravion-ux/secret-sniper

Find leaked API keys, tokens, passwords and private keys in any file,
folder, archive, git history or live website.
Detection and verification only - no exploitation.

Commands:
  scan TARGET          scan file / folder / archive / repo / stdin
  url URL              scan one website: page, JS assets, crawl, recon
  urls LIST            scan every URL listed in a file
  verify NAME          live-check the credentials in a saved scan
  export NAME -f F     export sarif / json / csv / html
  list | show | clear  manage saved scans
  ignore list|add|rm   manage the allowlist
  selftest             validate the detection engine
  help [COMMAND]       the full command reference
  interactive          guided menu

Zero required dependencies. `requests` is optional and only needed for
live credential verification (--verify).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import io
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple


# ═══════════════════════════════════════════════════════════════════════
# BRANDING
# ═══════════════════════════════════════════════════════════════════════
AUTHOR_NAME = "Priyanshu Kumar Thakur"
AUTHOR_HANDLE = "@pkt_143"
AUTHOR_ALIAS = "Gravion"
TELEGRAM_HANDLE = "@pkt_143"
TELEGRAM_LINK = "https://t.me/pkt_143"
GITHUB_LINK = "https://github.com/gravion-ux"
REPO_LINK = "https://github.com/gravion-ux/secret-sniper"
TOOL_NAME = "Secret Sniper"
TOOL_VERSION = "2.2.0"


# ═══════════════════════════════════════════════════════════════════════
# COLORS
# ═══════════════════════════════════════════════════════════════════════
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
W  = "\033[97m"
GR = "\033[90m"
B  = "\033[1m"
C  = "\033[96m"
M  = "\033[95m"
X  = "\033[0m"

SEV_COLOR = {
    "CRITICAL": R + B,
    "HIGH": R,
    "MEDIUM": Y,
    "LOW": C,
    "INFO": GR,
}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_SCORE = {"CRITICAL": 100, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 5}


def _safe_stdout() -> None:
    """Force UTF-8 output so the box-drawing/emoji survive a cp1252 console."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════
APP_DIR_NAME = ".secret_sniper"
LEGACY_APP_DIR_NAME = ".gravion_sniper"
DATA_DIR = os.path.join(os.path.expanduser("~"), APP_DIR_NAME, "scans")
ALLOWLIST_FILE = os.path.expanduser(f"~/{APP_DIR_NAME}/allowlist")
LOCAL_ALLOWLIST = ".secretignore"
LEGACY_LOCAL_ALLOWLIST = ".gravionignore"


def _migrate_legacy_data_dir() -> None:
    """Copy a legacy ~/.gravion_sniper tree into ~/.secret_sniper once.

    The old folder is deliberately left in place -- this tool never deletes
    user data, so the upgrade is a copy the user can remove themselves.
    """
    home = os.path.expanduser("~")
    legacy = os.path.join(home, LEGACY_APP_DIR_NAME)
    current = os.path.join(home, APP_DIR_NAME)
    if not os.path.isdir(legacy) or os.path.exists(current):
        return
    try:
        shutil.copytree(legacy, current)
    except Exception:
        pass

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".node_modules", "node_modules", "bower_components",
    "vendor", "__pycache__", ".venv", "venv", "env", ".tox", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".cache", "dist", "build", "target",
    ".next", ".nuxt", ".svelte-kit", ".turbo", ".parcel-cache", ".gradle",
    "coverage", "htmlcov", ".idea", ".vscode", ".terraform", "Pods",
    "DerivedData", "obj", "bin",
}

SKIP_EXTS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib", ".obj",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".tiff",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".iso", ".dmg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac", ".ogg", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pfb",
    ".pyc", ".pyo", ".class", ".jar", ".war", ".lock", ".pdb", ".wasm",
    ".min.js", ".min.css", ".map", ".db", ".sqlite", ".sqlite3", ".mdb",
}

# Archives are handled specially (they are expanded and scanned internally).
ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".whl", ".jar",
                ".war", ".ear", ".egg", ".apk", ".aar", ".nupkg", ".vsix"}

# Filenames that are almost always credential material.
SENSITIVE_FILENAMES = {
    ".env", ".env.local", ".env.development", ".env.production", ".env.staging",
    ".env.test", ".env.example", ".envrc", ".netrc", "_netrc", ".npmrc",
    ".pypirc", ".dockercfg", ".htpasswd", ".pgpass", ".git-credentials",
    "credentials", "credentials.json", "secrets.json", "secrets.yaml",
    "secrets.yml", "secrets.toml", "config.json", "service-account.json",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity",
    ".aws_credentials", ".boto", "kubeconfig", "config.yaml", "config.yml",
    ".htpasswd", "master.key", "credentials.yml", "applications.yml",
}

# Files whose mere presence is a signal, even without a regex hit.
SENSITIVE_FILE_SEVERITY = {
    ".env": "MEDIUM", ".netrc": "HIGH", "_netrc": "HIGH", ".npmrc": "MEDIUM",
    ".pypirc": "MEDIUM", ".htpasswd": "HIGH", ".pgpass": "HIGH",
    ".git-credentials": "CRITICAL", "id_rsa": "HIGH", "id_dsa": "HIGH",
    "id_ecdsa": "HIGH", "id_ed25519": "HIGH", "credentials": "HIGH",
    "master.key": "CRITICAL", ".aws_credentials": "HIGH",
}

MAX_ARCHIVE_ENTRY_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 2000

# Keywords that make a nearby string far more likely to be a real secret.
SECRET_KEYWORDS = re.compile(
    r"(?:pass(?:word|wd)?|pwd|secret|token|api[_\-]?key|apikey|api[_\-]?secret|"
    r"auth(?:orization)?|credential|private[_\-]?key|access[_\-]?key|"
    r"client[_\-]?secret|session[_\-]?id|signing[_\-]?key|encryption[_\-]?key|"
    r"jwt|bearer|refresh[_\-]?token|webhook[_\-]?url)",
    re.IGNORECASE,
)

PLACEHOLDER_WORDS = (
    "password", "example", "changeme", "change_me", "sample", "fake", "dummy",
    "your_", "your-", "yourkey", "yourpassword", "xxx", "todo", "fixme",
    "test_", "_test", "placeholder", "default", "replace", "insert",
    "put_your", "a1b2c3", "abcdef", "123456", "xxxxx", "none", "null", "nil",
    "true", "false", "localhost", "example.com", "foo", "bar", "baz", "abc123",
    "<", ">", "redacted", "hidden", "notreal", "dummy_key", "secret_here",
)


# ═══════════════════════════════════════════════════════════════════════
# PATTERN DATABASE
#   name      human readable rule name
#   regex     detection expression
#   severity  CRITICAL | HIGH | MEDIUM | LOW | INFO
#   category  grouping used by --only
#   confidence HIGH | MEDIUM | LOW
#   context   optional regex; must match within +/-CONTEXT_WINDOW chars
#   hint      optional literal; fast pre-filter, line must contain it (lower)
#   entropy   optional minimum Shannon entropy for the captured value
#   validate  optional callable key -> structural validation
#   desc      human readable description (used by SARIF / docs)
# ═══════════════════════════════════════════════════════════════════════
PATTERNS: List[Dict[str, Any]] = [
    # ── Cloud providers ───────────────────────────────────────────────
    dict(name="AWS Access Key ID", category="aws", severity="CRITICAL",
         confidence="HIGH", entropy=3.0, validator="aws",
         regex=r"\b((?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b",
         desc="AWS access key identifier (AKIA/ASIA prefix)."),
    dict(name="AWS Secret Access Key", category="aws", severity="CRITICAL",
         confidence="HIGH", entropy=3.5,
         regex=r"(?i:aws_secret_access_key|aws_secret_key|aws_session_token)"
               r"\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
         desc="AWS secret access key assignment."),
    dict(name="AWS MWS Key", category="aws", severity="HIGH", confidence="HIGH",
         regex=r"\b(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
               r"[0-9a-f]{4}-[0-9a-f]{12})\b",
         desc="Amazon Marketplace Web Service key."),
    dict(name="AWS Account ID", category="aws", severity="LOW", confidence="MEDIUM",
         context=r"account|acct|aws",
         regex=r"(?i:aws_account_id|aws_account)\s*[:=]\s*[\"']?([0-9]{12})[\"']?",
         desc="AWS account identifier (not a credential by itself)."),

    # ── Google / GCP ───────────────────────────────────────────────────
    dict(name="Google / Gemini API Key", category="google", severity="CRITICAL",
         confidence="HIGH", entropy=3.0, validator="google",
         regex=r"\b(AIza[0-9A-Za-z_\-]{35})\b",
         desc="Google Cloud / Maps / Firebase / Gemini API key."),
    dict(name="Google OAuth Client Secret", category="google", severity="CRITICAL",
         confidence="HIGH", entropy=3.0,
         regex=r"\b(GOCSPX-[A-Za-z0-9_\-]{28})\b",
         desc="Google OAuth 2.0 client secret."),
    dict(name="Google OAuth Client ID", category="google", severity="LOW",
         confidence="HIGH",
         regex=r"\b([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)\b",
         desc="Google OAuth 2.0 client identifier (public half)."),
    dict(name="GCP Service Account", category="gcp", severity="CRITICAL",
         confidence="HIGH",
         regex=r"[\"']type[\"']\s*:\s*[\"']service_account[\"']",
         desc="GCP service-account JSON key material."),
    dict(name="GCP Service Account Private Key", category="gcp",
         severity="CRITICAL", confidence="HIGH",
         regex=r"[\"']private_key[\"']\s*:\s*[\"'](-----BEGIN[A-Z ]*PRIVATE KEY-----)",
         desc="Embedded service-account private key."),
    dict(name="Firebase Cloud Messaging Key", category="firebase", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(AAAA[A-Za-z0-9_\-]{7}:APA91b[A-Za-z0-9_\-]{130,})\b",
         desc="Firebase Cloud Messaging server key."),
    dict(name="Firebase URL", category="firebase", severity="LOW", confidence="HIGH",
         regex=r"\b(https://[a-z0-9\-]+\.firebaseio\.com)\b",
         desc="Firebase realtime-database endpoint."),

    # ── Azure ──────────────────────────────────────────────────────────
    dict(name="Azure Storage Account Key", category="azure", severity="CRITICAL",
         confidence="HIGH", entropy=3.5,
         regex=r"(?i:AccountKey|account_key)\s*=\s*([A-Za-z0-9+/=]{86,92})",
         desc="Azure storage account access key."),
    dict(name="Azure SAS Token", category="azure", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(sv=\d{4}-\d{2}-\d{2}&(?:sr|sp|sig|se)=[^\s&\"']{8,})",
         desc="Azure shared access signature query string."),
    dict(name="Azure AD Client Secret", category="azure", severity="CRITICAL",
         confidence="HIGH", entropy=3.0,
         regex=r"(?i:azure_ad_client_secret|azure_client_secret|client_secret)"
               r"\s*[:=]\s*[\"']([A-Za-z0-9~._\-]{34,})[\"']",
         desc="Azure AD / Entra client secret."),

    # ── GitHub ─────────────────────────────────────────────────────────
    dict(name="GitHub PAT (classic)", category="github", severity="CRITICAL",
         confidence="HIGH", entropy=3.0, validator="github",
         regex=r"\b(ghp_[A-Za-z0-9]{36})\b",
         desc="Classic GitHub personal access token."),
    dict(name="GitHub Fine-Grained PAT", category="github", severity="CRITICAL",
         confidence="HIGH", entropy=3.0, validator="github",
         regex=r"\b(github_pat_[A-Za-z0-9_]{82})\b",
         desc="Fine-grained GitHub personal access token."),
    dict(name="GitHub OAuth Token", category="github", severity="HIGH",
         confidence="HIGH", validator="github",
         regex=r"\b(gho_[A-Za-z0-9]{36})\b",
         desc="GitHub OAuth access token."),
    dict(name="GitHub App Token", category="github", severity="HIGH",
         confidence="HIGH", validator="github",
         regex=r"\b(ghs_[A-Za-z0-9]{36})\b",
         desc="GitHub App installation token."),
    dict(name="GitHub User Token", category="github", severity="HIGH",
         confidence="HIGH", validator="github",
         regex=r"\b(ghu_[A-Za-z0-9]{36})\b",
         desc="GitHub user-to-server token."),
    dict(name="GitHub Refresh Token", category="github", severity="HIGH",
         confidence="HIGH", validator="github",
         regex=r"\b(ghr_[A-Za-z0-9]{36})\b",
         desc="GitHub refresh token."),

    # ── GitLab / Bitbucket ─────────────────────────────────────────────
    dict(name="GitLab PAT", category="gitlab", severity="CRITICAL",
         confidence="HIGH", entropy=3.0,
         regex=r"\b(glpat-[A-Za-z0-9_\-]{20})\b",
         desc="GitLab personal access token."),
    dict(name="GitLab Runner Token", category="gitlab", severity="CRITICAL",
         confidence="HIGH",
         regex=r"\b(GR1348941[0-9A-Za-z_\-]{20,})\b",
         desc="GitLab CI runner registration token."),
    dict(name="Bitbucket App Password", category="bitbucket", severity="HIGH",
         confidence="MEDIUM",
         context=r"bitbucket|bb_",
         regex=r"\b(bb_[0-9A-Za-z_\-]{20,})\b",
         desc="Bitbucket app password."),

    # ── Chat / messaging ───────────────────────────────────────────────
    dict(name="Slack Webhook", category="slack", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/"
               r"B[A-Z0-9]{6,}/[A-Za-z0-9]{20,})",
         desc="Slack incoming-webhook URL."),
    dict(name="Slack Bot Token", category="slack", severity="CRITICAL",
         confidence="HIGH", entropy=3.0, validator="slack",
         regex=r"\b(xoxb-[A-Za-z0-9\-]{10,72})\b",
         desc="Slack bot OAuth token."),
    dict(name="Slack User Token", category="slack", severity="CRITICAL",
         confidence="HIGH", entropy=3.0, validator="slack",
         regex=r"\b(xox[aprs]-[A-Za-z0-9\-]{10,72})\b",
         desc="Slack user/admin OAuth token."),
    dict(name="Slack App Token", category="slack", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(xapp-[A-Za-z0-9\-]{10,72})\b",
         desc="Slack app-level token."),
    dict(name="Discord Bot Token", category="discord", severity="CRITICAL",
         confidence="HIGH", entropy=3.0,
         regex=r"\b([MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27})\b",
         desc="Discord bot token."),
    dict(name="Discord Webhook", category="discord", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/"
               r"\d+/[\w\-]{20,})",
         desc="Discord webhook URL."),
    dict(name="Telegram Bot Token", category="telegram", severity="HIGH",
         confidence="HIGH", validator="telegram",
         regex=r"\b([0-9]{8,10}:[A-Za-z0-9_\-]{35})\b",
         desc="Telegram bot API token."),
    dict(name="Telegram Webhook Secret", category="telegram", severity="MEDIUM",
         confidence="MEDIUM",
         context=r"telegram|webhook",
         regex=r"(?i:telegram[_\-]?(?:webhook[_\-]?)?secret[_\-]?token)\s*[:=]\s*"
               r"[\"']?([A-Za-z0-9_\-]{16,64})[\"']?",
         desc="Telegram webhook secret token."),

    # ── Payments ───────────────────────────────────────────────────────
    dict(name="Stripe Live Secret Key", category="stripe", severity="CRITICAL",
         confidence="HIGH", entropy=3.0, validator="stripe",
         regex=r"\b(sk_live_[0-9a-zA-Z]{16,})\b",
         desc="Stripe live secret key."),
    dict(name="Stripe Restricted Key", category="stripe", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(rk_live_[0-9a-zA-Z]{16,})\b",
         desc="Stripe restricted live key."),
    dict(name="Stripe Test Secret Key", category="stripe", severity="MEDIUM",
         confidence="HIGH", validator="stripe",
         regex=r"\b(sk_test_[0-9a-zA-Z]{16,})\b",
         desc="Stripe test secret key (non-production)."),
    dict(name="Stripe Webhook Secret", category="stripe", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(whsec_[0-9a-zA-Z]{24,})\b",
         desc="Stripe webhook signing secret."),
    dict(name="PayPal Braintree Access Token", category="braintree",
         severity="CRITICAL", confidence="HIGH",
         regex=r"\b(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b",
         desc="Braintree production access token."),
    dict(name="Square Access Token", category="square", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(sq0atp-[0-9A-Za-z_\-]{22})\b",
         desc="Square access token."),
    dict(name="Square OAuth Secret", category="square", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(sq0csp-[0-9A-Za-z_\-]{43})\b",
         desc="Square OAuth client secret."),
    dict(name="PayPal Client Secret", category="paypal", severity="CRITICAL",
         confidence="HIGH", entropy=3.0,
         context=r"paypal|paypal_secret",
         regex=r"(?i:paypal[_\-]?secret|paypal[_\-]?client[_\-]?secret)\s*[:=]\s*"
               r"[\"']([A-Za-z0-9_\-]{24,})[\"']",
         desc="PayPal API client secret."),
    dict(name="Razorpay Key ID", category="razorpay", severity="MEDIUM",
         confidence="MEDIUM", context=r"razorpay",
         regex=r"\b(rzp_(?:live|test)_[A-Za-z0-9]{10,})\b",
         desc="Razorpay key identifier."),
    dict(name="Razorpay Key Secret", category="razorpay", severity="CRITICAL",
         confidence="HIGH", entropy=3.0, context=r"razorpay",
         regex=r"(?i:razorpay[_\-]?secret[_\-]?key)\s*[:=]\s*[\"']([A-Za-z0-9]{20,})[\"']",
         desc="Razorpay key secret."),

    # ── AI / LLM providers ─────────────────────────────────────────────
    dict(name="OpenAI API Key", category="openai", severity="CRITICAL",
         confidence="HIGH", entropy=3.0, validator="openai",
         regex=r"\b(sk-(?:proj-)?(?!ant-)[A-Za-z0-9_\-]{32,})\b",
         desc="OpenAI API key (legacy or project-scoped)."),
    dict(name="Anthropic API Key", category="anthropic", severity="CRITICAL",
         confidence="HIGH", entropy=3.0, validator="anthropic",
         regex=r"\b(sk-ant-[A-Za-z0-9_\-]{32,})\b",
         desc="Anthropic Claude API key."),
    dict(name="Hugging Face Token", category="huggingface", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(hf_[A-Za-z0-9]{34,40})\b",
         desc="Hugging Face access token."),
    dict(name="Cohere API Key", category="cohere", severity="HIGH",
         confidence="HIGH",
         regex=r"(?i:cohere[_\-]?(?:api[_\-]?)?key)\s*[:=]\s*[\"']([A-Za-z0-9]{40})[\"']",
         desc="Cohere API key."),
    dict(name="Replicate API Token", category="replicate", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(r8_[A-Za-z0-9]{37})\b",
         desc="Replicate API token."),
    dict(name="Groq API Key", category="groq", severity="HIGH", confidence="HIGH",
         regex=r"\b(gsk_[A-Za-z0-9]{48,})\b",
         desc="Groq API key."),
    dict(name="Mistral API Key", category="mistral", severity="HIGH",
         confidence="HIGH",
         regex=r"(?i:mistral[_\-]?api[_\-]?key)\s*[:=]\s*[\"']([A-Za-z0-9]{32})[\"']",
         desc="Mistral API key."),
    dict(name="OpenRouter API Key", category="openrouter", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(sk-or-v1-[A-Za-z0-9]{64})\b",
         desc="OpenRouter API key."),

    # ── Private keys / certificates ────────────────────────────────────
    dict(name="Private Key Header", category="private-key", severity="CRITICAL",
         confidence="HIGH",
         regex=r"(-----BEGIN [A-Z0-9 ]{0,48}PRIVATE KEY(?: BLOCK)?-----)",
         desc="PEM private-key header (complete block detected separately)."),
    dict(name="PuTTY Private Key", category="private-key", severity="CRITICAL",
         confidence="HIGH",
         regex=r"(-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----)",
         desc="PuTTY / SSH2 encrypted private key header."),
    dict(name="PKCS12 Keystore", category="private-key", severity="HIGH",
         confidence="MEDIUM",
         regex=r"(?i:keystore[_\-]?password|keystore[_\-]?pass)\s*[:=]\s*[\"']([^\"']{4,64})[\"']",
         desc="Keystore password (often protects a PKCS12 bundle)."),
    dict(name="Certificates (PEM)", category="certificate", severity="INFO",
         confidence="HIGH",
         regex=r"(-----BEGIN CERTIFICATE-----)",
         desc="X.509 certificate (public material, informational)."),

    # ── Tokens / sessions ──────────────────────────────────────────────
    dict(name="JSON Web Token", category="jwt", severity="HIGH", confidence="HIGH",
         regex=r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\."
               r"[A-Za-z0-9_\-]{10,})\b",
         desc="JSON Web Token."),
    dict(name="Bearer Token", category="generic", severity="MEDIUM",
         confidence="MEDIUM", entropy=3.5,
         regex=r"(?i:bearer)\s+([A-Za-z0-9\-._~+/]{20,})",
         desc="HTTP Authorization bearer token."),
    dict(name="Basic Auth Credentials", category="generic", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(https?://[^\s:/@]{1,64}:[^\s:/@]{1,64}@[^\s/]{2,})",
         desc="URL containing inline basic-auth credentials."),
    dict(name="Generic API Key", category="generic", severity="MEDIUM",
         confidence="LOW", entropy=3.5,
         context=r"api[_\-]?key|apikey|api[_\-]?secret|api[_\-]?token|"
                 r"access[_\-]?key",
         regex=r"[\"']([A-Za-z0-9_\-]{20,64})[\"']",
         desc="Quoted value assigned near an api-key keyword."),
    dict(name="Generic Secret", category="generic", severity="MEDIUM",
         confidence="LOW", entropy=3.5,
         context=r"(?:secret|private)[_\-]?(?:key|token|value)|client[_\-]?secret|"
                 r"signing[_\-]?key",
         regex=r"[\"']([A-Za-z0-9_\-./+=]{16,80})[\"']",
         desc="Quoted value assigned near a secret keyword."),
    dict(name="Generic Password", category="generic", severity="LOW",
         confidence="LOW",
         context=r"(?:password|passwd|pwd|passphrase)\s*[:=]",
         regex=r"[\"']([^\"'\s]{6,80})[\"']",
         desc="Quoted value assigned to a password keyword."),
    dict(name="Private Key Assignment", category="private-key", severity="CRITICAL",
         confidence="HIGH",
         context=r"private[_\-]?key",
         regex=r"(?i:private[_\-]?key)\s*[:=]\s*[\"']([A-Za-z0-9/+=]{32,})[\"']",
         desc="PEM body stored inline without the header."),

    # ── Package registries ─────────────────────────────────────────────
    dict(name="NPM Token", category="npm", severity="HIGH", confidence="HIGH",
         validator="npm",
         regex=r"\b(npm_[A-Za-z0-9]{36})\b",
         desc="npm access token."),
    dict(name="npm _authToken", category="npm", severity="HIGH", confidence="HIGH",
         regex=r"(?i:_authToken)\s*=\s*([A-Za-z0-9_\-]{20,})",
         desc="npm .npmrc _authToken entry."),
    dict(name="PyPI Token", category="pypi", severity="HIGH", confidence="HIGH",
         regex=r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b",
         desc="PyPI upload token."),
    dict(name="PyPI Password", category="pypi", severity="HIGH", confidence="HIGH",
         context=r"pypi|password",
         regex=r"(?i:pypi[_\-]?password)\s*[:=]\s*[\"']([^\"']{8,64})[\"']",
         desc="PyPI account password."),
    dict(name="Docker Hub PAT", category="docker", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(dckr_pat_[A-Za-z0-9_\-]{22,})\b",
         desc="Docker Hub personal access token."),
    dict(name="Docker Registry Auth", category="docker", severity="HIGH",
         confidence="HIGH",
         regex=r"(?i:docker[_\-]?(?:password|hub[_\-]?password))\s*[:=]\s*[\"']([^\"']{8,64})[\"']",
         desc="Docker registry password."),

    # ── Databases / infrastructure ─────────────────────────────────────
    dict(name="PostgreSQL Connection String", category="database",
         severity="CRITICAL", confidence="HIGH",
         regex=r"\b(postgres(?:ql)?://[^\s:/@]{1,64}:[^\s:/@]{1,64}@[^\s/?]{2,})",
         desc="PostgreSQL URI with inline credentials."),
    dict(name="MySQL/MariaDB Connection String", category="database",
         severity="CRITICAL", confidence="HIGH",
         regex=r"\b(mysql://[^\s:/@]{1,64}:[^\s:/@]{1,64}@[^\s/?]{2,})",
         desc="MySQL / MariaDB URI with inline credentials."),
    dict(name="MongoDB Connection String", category="database",
         severity="CRITICAL", confidence="HIGH",
         regex=r"\b(mongodb(?:\+srv)?://[^\s:/@]{1,64}:[^\s:/@]{1,64}@[^\s/?]{2,})",
         desc="MongoDB URI with inline credentials."),
    dict(name="Redis Connection String", category="database", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(redis(?:s)?://[^\s:/@]{0,64}:[^\s:/@]{1,64}@[^\s/?]{2,})",
         desc="Redis URI with inline credentials."),
    dict(name="AMQP Connection String", category="database", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(amqps?://[^\s:/@]{1,64}:[^\s:/@]{1,64}@[^\s/?]{2,})",
         desc="AMQP (RabbitMQ) URI with inline credentials."),
    dict(name="Elasticsearch Credentials", category="database", severity="HIGH",
         confidence="MEDIUM",
         regex=r"(?i:elastic[_\-]?(?:search)?[_\-]?password)\s*[:=]\s*[\"']([^\"']{6,64})[\"']",
         desc="Elasticsearch password."),
    dict(name="Supabase Service Key", category="supabase",
         severity="CRITICAL", confidence="HIGH", validator="supabase",
         regex=r"\b(sbp_[a-f0-9]{40})\b",
         desc="Supabase service-role / project key."),
    dict(name="PlanetScale Password", category="database", severity="HIGH",
         confidence="MEDIUM",
         regex=r"(?i:planetscale[_\-]?password)\s*[:=]\s*[\"']([^\"']{8,64})[\"']",
         desc="PlanetScale database password."),
    dict(name="Snowflake Credentials", category="database", severity="HIGH",
         confidence="HIGH",
         context=r"snowflake",
         regex=r"(?i:snowflake[_\-]?(?:password|secret))\s*[:=]\s*[\"']([^\"']{8,64})[\"']",
         desc="Snowflake account password / secret."),
    dict(name="BigQuery Service Account", category="database", severity="HIGH",
         confidence="MEDIUM",
         regex=r"(?i:bigquery[_\-]?(?:key|json))\s*[:=]\s*[\"']?([^\"'\s]{20,})",
         desc="BigQuery service-account key reference."),

    # ── Infrastructure as code ─────────────────────────────────────────
    dict(name="Terraform State Password", category="iac", severity="HIGH",
         confidence="MEDIUM",
         regex=r"(?i:\"?password\"?\s*:\s*\"([^\"]{6,64})\")",
         desc="Password recorded inside Terraform state."),

    # ── Cloud / hosting ────────────────────────────────────────────────
    dict(name="Cloudflare API Token", category="cloudflare", severity="CRITICAL",
         confidence="HIGH",
         regex=r"\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})\b",
         desc="Cloudflare API token."),
    dict(name="Cloudflare Global API Key", category="cloudflare", severity="CRITICAL",
         confidence="HIGH",
         context=r"cloudflare",
         regex=r"(?i:cloudflare[_\-]?global[_\-]?api[_\-]?key)\s*[:=]\s*[\"']([a-f0-9]{37})[\"']",
         desc="Cloudflare global API key."),
    dict(name="DigitalOcean PAT", category="digitalocean", severity="CRITICAL",
         confidence="HIGH",
         regex=r"\b(dop_v1_[a-f0-9]{64})\b",
         desc="DigitalOcean personal access token."),
    dict(name="DigitalOcean OAuth", category="digitalocean", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(doo_v1_[a-f0-9]{64})\b",
         desc="DigitalOcean OAuth token."),
    dict(name="Linode API Token", category="linode", severity="HIGH",
         confidence="HIGH",
         regex=r"(?i:linode[_\-]?api[_\-]?key)\s*[:=]\s*[\"']([A-Za-z0-9]{64})[\"']",
         desc="Linode API key."),
    dict(name="Vultr API Key", category="vultr", severity="HIGH",
         confidence="MEDIUM",
         regex=r"(?i:vultr[_\-]?api[_\-]?key)\s*[:=]\s*[\"']([A-Za-z0-9]{36,})[\"']",
         desc="Vultr API key."),
    dict(name="Heroku API Key", category="heroku", severity="HIGH",
         confidence="MEDIUM", entropy=3.5,
         regex=r"(?i:heroku[_\-]?api[_\-]?key)\s*[:=]\s*[\"']([A-Za-z0-9]{36,48})[\"']",
         desc="Heroku platform API key."),

    # ── SaaS / integrations ────────────────────────────────────────────
    dict(name="SendGrid API Key", category="sendgrid", severity="CRITICAL",
         confidence="HIGH", validator="sendgrid",
         regex=r"\b(SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64})\b",
         desc="SendGrid API key."),
    dict(name="Mailgun API Key", category="mailgun", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(key-[a-f0-9]{32})\b",
         desc="Mailgun API key."),
    dict(name="Mailgun Signing Key", category="mailgun", severity="HIGH",
         confidence="HIGH",
         regex=r"(?i:mailgun[_\-]?(?:webhook[_\-]?)?signing[_\-]?key)\s*[:=]\s*"
               r"[\"']([a-f0-9]{32,64})[\"']",
         desc="Mailgun webhook signing key."),
    dict(name="Mailchimp API Key", category="mailchimp", severity="HIGH",
         confidence="HIGH",
         regex=r"\b([0-9a-f]{32}-us\d{1,2})\b",
         desc="Mailchimp API key (datacenter suffix)."),
    dict(name="Postmark Server Token", category="postmark", severity="HIGH",
         confidence="HIGH",
         regex=r"(?i:postmark[_\-]?(?:server[_\-]?)?token)\s*[:=]\s*"
               r"[\"']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})[\"']",
         desc="Postmark server API token."),
    dict(name="Twilio Account SID", category="twilio", severity="MEDIUM",
         confidence="MEDIUM", context=r"twilio|account.?sid",
         regex=r"\b(AC[a-f0-9]{32})\b",
         desc="Twilio account identifier (not a secret by itself)."),
    dict(name="Twilio API Key", category="twilio", severity="HIGH",
         confidence="MEDIUM", context=r"twilio",
         regex=r"\b(SK[a-f0-9]{32})\b",
         desc="Twilio API key secret."),
    dict(name="Twilio Auth Token", category="twilio", severity="CRITICAL",
         confidence="HIGH",
         regex=r"(?i:twilio[_\-]?auth[_\-]?token)\s*[:=]\s*[\"']([a-f0-9]{32})[\"']",
         desc="Twilio account auth token."),
    dict(name="Segment Public Write Key", category="segment", severity="MEDIUM",
         confidence="MEDIUM",
         regex=r"\b([0-9a-z]{24})\b",
         context=r"segment", entropy=3.5,
         desc="Segment source write key."),
    dict(name="Sentry Auth Token", category="sentry", severity="HIGH",
         confidence="HIGH",
         regex=r"(?i:sentry[_\-]?(?:auth[_\-]?token|dsn))\s*[:=]\s*"
               r"[\"']?(https://[0-9a-f]{32}@[A-Za-z0-9.\-]+/[0-9]+)",
         desc="Sentry DSN / auth token."),
    dict(name="Algolia Admin Key", category="algolia", severity="HIGH",
         confidence="HIGH",
         regex=r"(?i:algolia[_\-]?(?:admin[_\-]?key|api[_\-]?key))\s*[:=]\s*"
               r"[\"']([a-f0-9]{32})[\"']",
         desc="Algolia admin API key."),
    dict(name="Linear API Key", category="linear", severity="HIGH", confidence="HIGH",
         regex=r"\b(lin_api_[A-Za-z0-9]{40})\b",
         desc="Linear API key."),
    dict(name="Notion Integration Token", category="notion", severity="HIGH",
         confidence="HIGH", context=r"notion",
         regex=r"\b(secret_[A-Za-z0-9]{43})\b",
         desc="Notion internal integration token."),
    dict(name="Notion API Token", category="notion", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(ntn_[A-Za-z0-9]{40})\b",
         desc="Notion API token."),
    dict(name="Airtable PAT", category="airtable", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(pat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64})\b",
         desc="Airtable personal access token."),
    dict(name="Airtable API Key", category="airtable", severity="MEDIUM",
         confidence="MEDIUM", context=r"airtable", entropy=3.0,
         regex=r"\b(key[A-Za-z0-9]{14})\b",
         desc="Airtable legacy API key."),
    dict(name="Datadog API Key", category="datadog", severity="MEDIUM",
         confidence="MEDIUM", context=r"datadog", entropy=3.5,
         regex=r"\b(dd[a-z0-9]{32,36})\b",
         desc="Datadog API key."),
    dict(name="Postman API Key", category="postman", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b",
         desc="Postman API key."),
    dict(name="Vercel Token", category="vercel", severity="HIGH", confidence="MEDIUM",
         regex=r"(?i:vercel[_\-]?token)\s*[:=]\s*[\"']([A-Za-z0-9]{24})[\"']",
         desc="Vercel access token."),
    dict(name="Netlify Auth Token", category="netlify", severity="HIGH",
         confidence="HIGH",
         regex=r"(?i:netlify[_\-]?auth[_\-]?token)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']",
         desc="Netlify personal access token."),
    dict(name="Railway Token", category="railway", severity="HIGH",
         confidence="MEDIUM",
         regex=r"(?i:railway[_\-]?(?:token|api[_\-]?key))\s*[:=]\s*[\"']([A-Za-z0-9_\-]{20,})[\"']",
         desc="Railway deployment token."),
    dict(name="CircleCI Token", category="circleci", severity="HIGH",
         confidence="HIGH",
         regex=r"(?i:circle[_\-]?ci[_\-]?token)\s*[:=]\s*[\"']([a-f0-9]{40})[\"']",
         desc="CircleCI API token."),
    dict(name="Codecov Token", category="codecov", severity="MEDIUM",
         confidence="MEDIUM",
         regex=r"(?i:codecov[_\-]?token)\s*[:=]\s*[\"']([A-Za-z0-9]{32,})[\"']",
         desc="Codecov upload token."),
    dict(name="Shopify Access Token", category="shopify", severity="CRITICAL",
         confidence="HIGH",
         regex=r"\b(shpat_[a-fA-F0-9]{32})\b",
         desc="Shopify custom-app access token."),
    dict(name="Shopify Custom App Token", category="shopify", severity="CRITICAL",
         confidence="HIGH",
         regex=r"\b(shpca_[a-fA-F0-9]{32})\b",
         desc="Shopify custom-app token."),
    dict(name="Shopify Private App Token", category="shopify", severity="CRITICAL",
         confidence="HIGH",
         regex=r"\b(shppa_[a-fA-F0-9]{32})\b",
         desc="Shopify private-app token."),
    dict(name="Shopify Shared Secret", category="shopify", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(shpss_[a-fA-F0-9]{32})\b",
         desc="Shopify shared secret."),
    dict(name="Square OAuth Client ID", category="square", severity="LOW",
         confidence="HIGH",
         regex=r"\b(sq0idp-[0-9A-Za-z_\-]{22})\b",
         desc="Square OAuth client identifier (public half)."),

    # ── Auth providers / identity ──────────────────────────────────────
    dict(name="Okta Token", category="okta", severity="CRITICAL", confidence="HIGH",
         regex=r"(?i:okta[_\-]?(?:api[_\-]?token|api[_\-]?key))\s*[:=]\s*"
               r"[\"']([A-Za-z0-9_\-]{40,})[\"']",
         desc="Okta API token."),
    dict(name="Auth0 Client Secret", category="auth0", severity="CRITICAL",
         confidence="HIGH", entropy=3.0,
         regex=r"(?i:auth0[_\-]?(?:client[_\-]?secret|secret))\s*[:=]\s*"
               r"[\"']([A-Za-z0-9_\-]{32,})[\"']",
         desc="Auth0 client secret."),
    dict(name="Clerk Secret Key", category="clerk", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(sk_(?:test|live)_[A-Za-z0-9]{20,})\b",
         desc="Clerk secret key."),
    dict(name="Doppler API Token", category="doppler", severity="HIGH",
         confidence="HIGH",
         regex=r"(?i:doppler[_\-]?token)\s*[:=]\s*[\"'](dp\.[A-Za-z0-9_\-]{20,})[\"']",
         desc="Doppler service token."),
    dict(name="1Password Service Account Token", category="onepassword",
         severity="CRITICAL", confidence="HIGH",
         regex=r"\b(ops_eyJ[A-Za-z0-9_\-]{40,})\b",
         desc="1Password service-account token."),

    # ── Observability / analytics ──────────────────────────────────────
    dict(name="New Relic License Key", category="newrelic", severity="HIGH",
         confidence="HIGH",
         regex=r"(?i:newrelic[_\-]?(?:license[_\-]?key|key))\s*[:=]\s*"
               r"[\"']([a-f0-9]{40})[\"']",
         desc="New Relic license key."),
    dict(name="Mixpanel Token", category="mixpanel", severity="MEDIUM",
         confidence="MEDIUM", context=r"mixpanel", entropy=3.5,
         regex=r"\b([a-f0-9]{32})\b",
         desc="Mixpanel project token."),
    dict(name="Amplitude API Key", category="amplitude", severity="MEDIUM",
         confidence="MEDIUM", context=r"amplitude", entropy=3.5,
         regex=r"\b([a-f0-9]{32})\b",
         desc="Amplitude project API key."),

    # ── Social ─────────────────────────────────────────────────────────
    dict(name="Twitter/X Bearer Token", category="twitter", severity="HIGH",
         confidence="MEDIUM", context=r"twitter|bearer", entropy=4.0,
         regex=r"\b(A{22}[A-Za-z0-9%]{80,120})\b",
         desc="Twitter/X API bearer token."),
    dict(name="Facebook Access Token", category="facebook", severity="HIGH",
         confidence="HIGH",
         regex=r"\b(EAACEdEose0cBA[0-9A-Za-z]+)\b",
         desc="Facebook graph API access token."),

    # ── Build / CI ─────────────────────────────────────────────────────
    dict(name="Bazel Remote Cache Token", category="ci", severity="MEDIUM",
         confidence="MEDIUM",
         regex=r"(?i:bazel[_\-]?rc[_\-]?token)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']",
         desc="Bazel remote-cache auth token."),
    dict(name="Artifactory Token", category="ci", severity="HIGH",
         confidence="MEDIUM",
         regex=r"(?i:artifactory[_\-]?(?:api[_\-]?key|token))\s*[:=]\s*"
               r"[\"']([A-Za-z0-9_\-]{16,})[\"']",
         desc="Artifactory API key / token."),
    dict(name="Azure DevOps PAT", category="azure", severity="CRITICAL",
         confidence="HIGH",
         regex=r"\b([a-z0-9]{52})\b",
         context=r"azure[_\-]?devops|vsts|pat", entropy=3.0,
         desc="Azure DevOps personal access token."),
]

CONTEXT_WINDOW = 60


# ═══════════════════════════════════════════════════════════════════════
# STRUCTURAL VALIDATORS
#   A validator inspects the captured value and returns (ok, reason).
#   It never performs network I/O - live checks live in the verifier.
# ═══════════════════════════════════════════════════════════════════════
def _validate_aws_key(value: str) -> Tuple[bool, str]:
    """AWS key IDs are base32-ish uppercase; reject impossible shapes."""
    if not re.fullmatch(r"[A-Z0-9]{20}", value):
        return False, "not 20 uppercase alphanumerics"
    if not value.startswith(("AKIA", "ASIA", "AROA", "AIDA", "AGPA", "ANPA",
                             "ANVA", "AIPA")):
        return False, "unknown AWS key prefix"
    if len(set(value)) < 6:
        return False, "insufficient character variety"
    return True, "valid AWS key-id shape"


PEM_BLOCK_RE = re.compile(
    r"-----BEGIN (?P<label>[A-Z0-9 ]{0,48}PRIVATE KEY(?: BLOCK)?)-----"
    r"[\s\S]{0,16384}?"
    r"-----END (?P<endlabel>[A-Z0-9 ]{0,48}PRIVATE KEY(?: BLOCK)?)-----"
)


def _validate_jwt(value: str) -> Tuple[bool, str]:
    """Decode the JOSE header and payload; reject malformed tokens."""
    parts = value.split(".")
    if len(parts) != 3:
        return False, "not three JWT segments"
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
    except Exception:
        return False, "header is not valid base64url JSON"
    if not isinstance(header, dict) or "alg" not in header:
        return False, "header missing alg"
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except Exception:
        return False, "payload is not valid base64url JSON"
    if not isinstance(payload, dict):
        return False, "payload is not a JSON object"
    return True, f"valid JWT (alg={header.get('alg')})"


def _validate_github_pat(value: str) -> Tuple[bool, str]:
    if re.fullmatch(r"gh[pousr]_[A-Za-z0-9]{36}", value):
        return True, "valid GitHub token shape"
    if re.fullmatch(r"github_pat_[A-Za-z0-9_]{82}", value):
        return True, "valid fine-grained GitHub token shape"
    return False, "wrong token length or alphabet"


def _validate_stripe(value: str) -> Tuple[bool, str]:
    m = re.fullmatch(r"sk_(live|test)_([0-9a-zA-Z]{16,})", value)
    if not m:
        return False, "wrong Stripe key shape"
    return True, f"Stripe {m.group(1)} key"


def _validate_slack(value: str) -> Tuple[bool, str]:
    if not re.fullmatch(r"xox[abprs]-[A-Za-z0-9\-]{10,72}", value):
        return False, "wrong Slack token shape"
    return True, "valid Slack token shape"


def _validate_anthropic(value: str) -> Tuple[bool, str]:
    if not value.startswith("sk-ant-"):
        return False, "missing sk-ant- prefix"
    return True, "valid Anthropic key shape"


def _validate_openai(value: str) -> Tuple[bool, str]:
    if value.startswith("sk-proj-"):
        return True, "project-scoped OpenAI key"
    if re.fullmatch(r"sk-[A-Za-z0-9]{48}", value):
        return True, "legacy OpenAI key"
    return False, "wrong OpenAI key shape"


def _validate_google(value: str) -> Tuple[bool, str]:
    if not re.fullmatch(r"AIza[0-9A-Za-z_\-]{35}", value):
        return False, "wrong Google API key shape"
    return True, "valid Google API key shape"


def _validate_private_key(value: str) -> Tuple[bool, str]:
    if not value.startswith("-----BEGIN"):
        return False, "missing PEM header"
    if "PRIVATE KEY" not in value:
        return False, "not a private-key block"
    return True, "PEM private key block"


def _validate_sendgrid(value: str) -> Tuple[bool, str]:
    if not re.fullmatch(r"SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}", value):
        return False, "wrong SendGrid key shape"
    return True, "valid SendGrid key shape"


def _validate_npm(value: str) -> Tuple[bool, str]:
    if not re.fullmatch(r"npm_[A-Za-z0-9]{36}", value):
        return False, "wrong npm token shape"
    return True, "valid npm token shape"


def _validate_telegram(value: str) -> Tuple[bool, str]:
    if not re.fullmatch(r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}", value):
        return False, "wrong Telegram token shape"
    return True, "valid Telegram token shape"


def _validate_supabase(value: str) -> Tuple[bool, str]:
    if not re.fullmatch(r"sbp_[a-f0-9]{40}", value):
        return False, "wrong Supabase key shape"
    return True, "valid Supabase key shape"


VALIDATORS: Dict[str, Callable[[str], Tuple[bool, str]]] = {
    "aws": _validate_aws_key,
    "jwt": _validate_jwt,
    "github": _validate_github_pat,
    "stripe": _validate_stripe,
    "slack": _validate_slack,
    "anthropic": _validate_anthropic,
    "openai": _validate_openai,
    "google": _validate_google,
    "private-key": _validate_private_key,
    "sendgrid": _validate_sendgrid,
    "npm": _validate_npm,
    "telegram": _validate_telegram,
    "supabase": _validate_supabase,
}


def _compile_patterns() -> List[Dict[str, Any]]:
    compiled: List[Dict[str, Any]] = []
    for spec in PATTERNS:
        flags = re.IGNORECASE if spec.get("case_insensitive") else 0
        try:
            regex = re.compile(spec["regex"], flags)
        except re.error as exc:                       # pragma: no cover - guard
            print(f"{R}Pattern error in '{spec['name']}': {exc}{X}")
            continue
        ctx = spec.get("context")
        compiled.append({
            **spec,
            "compiled": regex,
            "context_compiled": re.compile(ctx, re.IGNORECASE) if ctx else None,
            "hint": spec.get("hint"),
            "validator": VALIDATORS.get(spec.get("validator")),
        })
    return compiled


COMPILED = _compile_patterns()


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def redact(value: str, keep: int = 4) -> str:
    """Mask the middle of a secret, keeping a short recognisable prefix."""
    n = len(value)
    if n <= keep * 2:
        return "*" * n
    return value[:keep] + "*" * (n - keep * 2) + value[-keep:]


def should_redact(value: str) -> bool:
    """PEM headers are safe to show in full; the body is not."""
    return not (value.startswith("-----") and value.endswith("-----"))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_hash(s: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]+", s)) and len(s) in (32, 40, 64, 96, 128)


def looks_like_url(s: str) -> bool:
    return s.startswith(("http://", "https://", "ftp://", "ssh://", "git://"))


def looks_like_path(s: str) -> bool:
    return "/" in s and not looks_like_url(s)


def is_placeholder(s: str) -> bool:
    low = s.lower()
    return any(word in low for word in PLACEHOLDER_WORDS)


# A camelCase / PascalCase compound built from pronounceable word-like parts.
_CAMEL_SEGMENTS = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+")
# Punctuation that never appears inside a real credential but is everywhere in
# minified source code -- a match containing it is a piece of code, not a key.
_CODE_PUNCTUATION = set(",(){}[];:<>*&|\\?`~")


def _is_wordlike_part(part: str) -> bool:
    """True when one component of a compound name reads like a word.

    A component is wordlike when it is a plain lower-case word
    (``glossary``), an upper-case constant possibly carrying a version digit
    (``V2``, ``ORGANIZATION``), or a camelCase/PascalCase compound
    (``docsShell``). Long alternating letter/digit blobs such as
    ``a1b2c3d4`` are deliberately *not* wordlike -- those look like random
    credential material and must keep being reported.
    """
    if not part:
        return False
    if part.isalpha() and (part.islower() or part.isupper()):
        return True
    if re.fullmatch(r"[A-Z][A-Z0-9]*", part):
        return True
    if re.fullmatch(r"[a-z]+[0-9]+", part):
        return True
    segments = _CAMEL_SEGMENTS.findall(part)
    if len(segments) < 2:
        return False
    alpha = [segment for segment in segments if segment.isalpha()]
    if not alpha:
        return False
    if len(alpha) / len(segments) < 0.7:
        return False
    return sum(len(segment) for segment in alpha) / len(part) >= 0.75


def _is_short_camel_compound(value: str) -> bool:
    """True for a short camelCase method name such as ``getHost``.

    Values below the 8-character floor used by :func:`looks_like_identifier`
    are only treated as identifiers when they split into purely alphabetic
    segments and at least one of them starts with a capital. A short random
    secret such as ``Xq7bZ2`` keeps its digits and therefore stays reported.
    """
    if len(value) < 6:
        return False
    segments = _CAMEL_SEGMENTS.findall(value)
    if len(segments) < 2:
        return False
    if not all(segment.isalpha() for segment in segments):
        return False
    if not any(segment[:1].isupper() for segment in segments):
        return False
    return all(len(segment) >= 2 for segment in segments)


def looks_like_identifier(value: str) -> bool:
    """True when a value reads like a code identifier rather than a secret.

    Minified JavaScript bundles are full of quoted schema and field names such
    as ``OpenapiGetV1AccountApiKeysInput`` or ``specified_by_request``. The
    generic keyword-adjacent rules matched those and reported them as keys,
    which buried the real findings under noise -- one real bundle produced 86
    bogus HIGH findings and no useful signal. A random credential mixes
    character classes and breaks into nonsense segments; an identifier is
    built from word-like segments.

    Dotted paths are split into their components first, because a property
    path such as ``docsShell.glossary.term.secretKey`` is an identifier even
    though each individual component mixes cases.
    """
    if not value:
        return False

    parts = [part for part in re.split(r"[._-]+", value) if part]
    if len(parts) >= 2:
        # A multi-part name is an identifier only when every component is
        # word-like; one random component makes the whole value suspicious.
        return all(_is_wordlike_part(part) for part in parts)

    if len(value) < 8:
        return _is_short_camel_compound(value)

    segments = _CAMEL_SEGMENTS.findall(value)
    if len(segments) < 2:
        return False
    alpha = [segment for segment in segments if segment.isalpha()]
    if not alpha:
        return False
    if len(alpha) / len(segments) < 0.7:
        return False
    return sum(len(segment) for segment in alpha) / len(value) >= 0.75


# Provider object identifiers (a Stripe charge, customer, invoice, ...) are
# public references, not credentials. They share the generic "prefix_base62"
# shape with real keys, so the generic fallback rules must not report them.
NON_SECRET_ID_PREFIXES = (
    "acct_", "adj_", "bal_", "card_", "ch_", "cn_", "cs_", "cus_", "evt_",
    "fld_", "ic_", "in_", "ord_", "pi_", "plan_", "po_", "price_", "prod_",
    "pm_", "prv_", "qt_", "re_", "seti_", "si_", "src_", "sub_", "tr_", "txn_",
)


def looks_like_public_object_id(value: str) -> bool:
    """True when a value is a provider object id rather than a credential."""
    if not value:
        return False
    for prefix in NON_SECRET_ID_PREFIXES:
        if value.startswith(prefix):
            body = value[len(prefix):]
            if len(body) >= 10 and body.isalnum():
                return True
    return False


def looks_like_code_fragment(value: str) -> bool:
    """True when a matched value is really a slice of source code.

    Minified code reuses quote characters as delimiters, so a rule looking for
    a quoted value can capture everything between two unrelated quotes -- for
    example ``",l.username="``. Real credential values never contain brackets,
    commas or semicolons, so their presence means the match is code.
    """
    if not value:
        return True
    if any(char in _CODE_PUNCTUATION for char in value):
        return True
    return any(char.isspace() for char in value)


def hash_secret(s: str) -> str:
    """Stable short fingerprint used for allowlisting and de-duplication."""
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()[:16]


def display_path(path: str, root: Optional[str] = None) -> str:
    try:
        base = root or os.getcwd()
        rel = os.path.relpath(path, base)
        if not rel.startswith(".."):
            return rel.replace("\\", "/")
    except Exception:
        pass
    return path.replace("\\", "/")


def safe_read_bytes(path: str, max_bytes: int) -> Optional[bytes]:
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        with open(path, "rb") as fh:
            return fh.read()
    except Exception:
        return None


def decode_text(data: bytes) -> str:
    """Decode bytes to text, transparently handling UTF-16 and BOMs."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except Exception:
            pass
    if data[:3] == b"\xef\xbb\xbf":
        try:
            return data.decode("utf-8-sig")
        except Exception:
            pass
    return data.decode("utf-8", errors="replace")


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:2048]


# ── allowlist ─────────────────────────────────────────────────────────
def load_allowlist() -> Set[str]:
    entries: Set[str] = set()
    for path in (ALLOWLIST_FILE, LOCAL_ALLOWLIST, LEGACY_LOCAL_ALLOWLIST):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.add(line)
        except Exception:
            pass
    return entries


def save_allowlist(entries: Set[str], path: Optional[str] = None) -> None:
    path = path or ALLOWLIST_FILE
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# Secret Sniper allowlist\n")
        fh.write("# entries: 16-char hash, pattern name, or regex:...\n\n")
        for entry in sorted(entries):
            fh.write(entry + "\n")


def load_path_ignores() -> List[str]:
    """Glob-ish path patterns from .secretignore (one per line, # comments)."""
    patterns: List[str] = []
    if not os.path.exists(LOCAL_ALLOWLIST):
        return patterns
    try:
        with open(LOCAL_ALLOWLIST, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("regex:"):
                    patterns.append(line)
    except Exception:
        pass
    return patterns


def path_is_ignored(path: str, patterns: Sequence[str]) -> bool:
    if not patterns:
        return False
    normalised = path.replace("\\", "/")
    for pat in patterns:
        p = pat.rstrip("/")
        if not p:
            continue
        if normalised == p or normalised.endswith("/" + p):
            return True
        if p.endswith("*") and normalised.split("/")[-1].startswith(p[:-1]):
            return True
    return False


# ── entropy heuristics ────────────────────────────────────────────────
def entropy_scan(line: str, min_entropy: float = 4.2) -> List[Tuple[str, float]]:
    """Find high-entropy strings sitting next to a secret-ish keyword."""
    results: List[Tuple[str, float]] = []
    for match in re.finditer(
        r"(?i)([A-Za-z0-9_\-]{0,40})"
        r"(?:pass(?:word|wd)?|pwd|secret|token|api[_\-]?key|apikey|"
        r"api[_\-]?secret|api[_\-]?token|auth|credential|private[_\-]?key|"
        r"access[_\-]?key|client[_\-]?secret|session[_\-]?id|bearer|"
        r"signing[_\-]?key|encryption[_\-]?key|refresh[_\-]?token)"
        r"[\s\"'=:]{1,4}[\"']?([A-Za-z0-9+/=_\-\.!]{16,120})[\"']?",
        line,
    ):
        candidate = match.group(2)
        if not candidate or len(candidate) < 16:
            continue
        if not (any(ch.isdigit() for ch in candidate) and any(ch.isalpha() for ch in candidate)):
            continue
        if looks_like_hash(candidate) or looks_like_url(candidate) or looks_like_path(candidate):
            continue
        if is_placeholder(candidate):
            continue
        if candidate.lower().endswith((".py", ".js", ".ts", ".json", ".yaml", ".yml", ".go")):
            continue
        entropy = shannon_entropy(candidate)
        if entropy >= min_entropy:
            results.append((candidate, entropy))
    return results


def decode_b64_candidates(line: str) -> List[str]:
    """Find base64 blobs in a line and return their decoded text."""
    decoded: List[str] = []
    for match in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", line):
        blob = match.group(0)
        if len(blob) % 4:
            blob += "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(blob, validate=False)
        except (binascii.Error, ValueError):
            continue
        if len(raw) < 12:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if not text.isprintable():
            continue
        decoded.append(text)
    return decoded


def decode_hex_candidates(line: str) -> List[str]:
    """Find hex blobs in a line and return their decoded text."""
    decoded: List[str] = []
    for match in re.finditer(r"(?:0x)?([0-9a-fA-F]{32,})", line):
        blob = match.group(1)
        if len(blob) % 2:
            continue
        try:
            raw = bytes.fromhex(blob)
        except ValueError:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(text) < 12 or not text.isprintable():
            continue
        decoded.append(text)
    return decoded


# ═══════════════════════════════════════════════════════════════════════
# SCANNER
# ═══════════════════════════════════════════════════════════════════════
class SecretScanner:
    """Pattern + entropy + structure scanner for leaked credentials."""

    def __init__(self,
                 redact_mode: bool = True,
                 entropy: bool = True,
                 allowlist: Optional[Set[str]] = None,
                 only_cats: Optional[Set[str]] = None,
                 min_severity: str = "LOW",
                 decode_encoded: bool = True,
                 min_entropy: float = 4.2):
        self.redact_mode = redact_mode
        self.entropy = entropy
        self.decode_encoded = decode_encoded
        self.min_entropy = min_entropy
        self.allowlist = allowlist or set()
        self.only_cats = only_cats
        self.min_rank = SEV_ORDER.get(min_severity.upper(), 3)
        # Guards against unbounded recursion when scanning decoded payloads.
        # The guard is per-thread: when one instance is shared across many
        # workers, a shared counter would let one worker's encoded-payload
        # scan suppress every other worker's encoded-secret detection.
        self._state = threading.local()
        self._depth = 0

    @property
    def _depth(self) -> int:
        """Recursion depth of the calling thread."""
        return getattr(self._state, "depth", 0)

    @_depth.setter
    def _depth(self, value: int) -> None:
        self._state.depth = value

    # ── allowlist ──────────────────────────────────────────────────────
    def _is_allowlisted(self, pattern_name: str, value: str) -> bool:
        if not self.allowlist:
            return False
        if hash_secret(value) in self.allowlist:
            return True
        if pattern_name in self.allowlist:
            return True
        for entry in self.allowlist:
            if entry.startswith("regex:"):
                try:
                    if re.search(entry[6:], value):
                        return True
                except re.error:
                    pass
        return False

    # ── severity helpers ───────────────────────────────────────────────
    @staticmethod
    def _bump(severity: str, step: int = 1) -> str:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            idx = order.index(severity)
        except ValueError:
            return severity
        return order[min(len(order) - 1, idx + step)]

    def _confidence_bonus(self, confidence: str) -> int:
        return {"HIGH": 2, "MEDIUM": 1, "LOW": 0}.get(confidence, 0)

    # ── core line scanning ─────────────────────────────────────────────
    def _scan_line(self, line: str, source: str, line_num: int,
                   local_seen: Set[Tuple[str, str, str]],
                   skip_header_lines: Optional[Set[int]] = None) -> List[Dict]:
        findings: List[Dict] = []
        lowered = line.lower()

        for spec in COMPILED:
            if self.only_cats and spec["category"] not in self.only_cats:
                continue
            if SEV_ORDER.get(spec["severity"], 99) > self.min_rank:
                continue
            # A complete PEM block is already reported by _scan_pem_blocks;
            # do not report its header line a second time.
            if (spec["name"] == "Private Key Header"
                    and skip_header_lines and line_num in skip_header_lines):
                continue

            hint = spec.get("hint")
            if hint and hint.lower() not in lowered:
                continue

            try:
                matches = list(spec["compiled"].finditer(line))
            except Exception:
                continue

            for match in matches:
                if spec.get("context_compiled"):
                    lo = max(0, match.start() - CONTEXT_WINDOW)
                    hi = min(len(line), match.end() + CONTEXT_WINDOW)
                    if not spec["context_compiled"].search(line[lo:hi]):
                        continue

                match_val = match.group(1) if match.groups() else match.group(0)
                if not match_val:
                    continue

                # The low-confidence generic rules are the fallback for
                # unknown formats. Code identifiers in minified bundles look
                # exactly like quoted values, and provider object ids
                # ("ch_3...", "cus_...") look like keys, so they are filtered
                # out here instead of drowning the real findings.
                if (spec["category"] == "generic"
                        and spec["confidence"] == "LOW"
                        and (looks_like_identifier(match_val)
                             or looks_like_code_fragment(match_val)
                             or looks_like_public_object_id(match_val))):
                    continue

                min_entropy = spec.get("entropy")
                if min_entropy is not None:
                    if shannon_entropy(match_val) < min_entropy:
                        continue
                    if is_placeholder(match_val) and spec.get("confidence") != "HIGH":
                        continue

                validator = spec.get("validator")
                if validator is not None:
                    ok, reason = validator(match_val)
                    if not ok:
                        continue
                else:
                    reason = ""

                key = (spec["name"], hash_secret(match_val), f"{line_num}")
                if key in local_seen:
                    continue
                local_seen.add(key)

                if self._is_allowlisted(spec["name"], match_val):
                    continue

                severity = spec["severity"]
                # A live-looking credential next to a secret keyword is worse.
                if SECRET_KEYWORDS.search(line) and severity in ("MEDIUM", "LOW"):
                    severity = self._bump(severity, 1)

                shown = (redact(match_val)
                         if (self.redact_mode and should_redact(match_val))
                         else match_val)

                findings.append({
                    "pattern": spec["name"],
                    "severity": severity,
                    "confidence": spec["confidence"],
                    "category": spec["category"],
                    "file": source,
                    "line": line_num,
                    "match": shown,
                    "raw_length": len(match_val),
                    "hash": hash_secret(match_val),
                    "validation": reason,
                    "risk": SEV_SCORE.get(severity, 25)
                            + self._confidence_bonus(spec["confidence"]),
                    "_raw": match_val,
                })

        # ── entropy-based detection ───────────────────────────────────
        if self.entropy and (not self.only_cats or "entropy" in self.only_cats):
            if self.min_rank >= SEV_ORDER["MEDIUM"]:
                for candidate, entropy in entropy_scan(line, self.min_entropy):
                    key = ("High Entropy String", hash_secret(candidate), f"{line_num}")
                    if key in local_seen:
                        continue
                    local_seen.add(key)
                    if self._is_allowlisted("High Entropy String", candidate):
                        continue
                    shown = (redact(candidate)
                             if (self.redact_mode and should_redact(candidate))
                             else candidate)
                    findings.append({
                        "pattern": "High Entropy String",
                        "severity": "MEDIUM",
                        "confidence": "LOW",
                        "category": "entropy",
                        "file": source,
                        "line": line_num,
                        "match": shown,
                        "raw_length": len(candidate),
                        "hash": hash_secret(candidate),
                        "validation": f"entropy={entropy:.2f}",
                        "risk": SEV_SCORE["MEDIUM"],
                        "_raw": candidate,
                    })

        # ── encoded payloads ───────────────────────────────────────────
        if self.decode_encoded and (not self.only_cats or "encoded" in self.only_cats):
            findings.extend(self._scan_encoded(line, source, line_num, local_seen))

        return findings

    def _scan_encoded(self, line: str, source: str, line_num: int,
                      local_seen: Set[Tuple[str, str, str]]) -> List[Dict]:
        """Recursively scan base64 / hex encoded payloads found in a line.

        Bounded to one nesting level so a base64-of-base64 blob cannot
        spin the scanner.
        """
        findings: List[Dict] = []
        if self._depth >= 1:
            return findings
        self._depth += 1
        try:
            for encoding, decoder in (("base64", decode_b64_candidates),
                                      ("hex", decode_hex_candidates)):
                try:
                    payloads = decoder(line)
                except Exception:
                    payloads = []
                for payload in payloads:
                    inner = self.scan_text(payload, source=f"{source} [{encoding}]",
                                           base_line=line_num)
                    for hit in inner:
                        hit["pattern"] = f"Encoded Secret ({encoding}) · {hit['pattern']}"
                        hit["severity"] = self._bump(hit["severity"], 1)
                        hit["risk"] = SEV_SCORE.get(hit["severity"], 25)
                        findings.append(hit)
        finally:
            self._depth -= 1
        return findings

    def _scan_pem_blocks(self, text: str, source: str) -> Tuple[List[Dict], Set[int]]:
        """Detect complete PEM private-key blocks spanning multiple lines.

        Returns the findings plus the set of line numbers occupied by a
        complete block, so the single-line header rule can stand down.
        """
        findings: List[Dict] = []
        covered: Set[int] = set()
        if self.only_cats and "private-key" not in self.only_cats:
            return findings, covered
        if SEV_ORDER.get("CRITICAL", 0) > self.min_rank:
            return findings, covered

        for match in PEM_BLOCK_RE.finditer(text):
            block = match.group(0)
            start_line = text.count("\n", 0, match.start()) + 1
            end_line = text.count("\n", 0, match.end()) + 1
            covered.update(range(start_line, end_line + 1))
            label = match.group("label").strip()
            if self._is_allowlisted("Private Key (PEM)", block):
                continue
            shown = (f"-----BEGIN {label}----- ... "
                     f"[{len(block)} bytes redacted]")
            findings.append({
                "pattern": "Private Key (PEM)",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "category": "private-key",
                "file": source,
                "line": start_line,
                "match": shown,
                "raw_length": len(block),
                "hash": hash_secret(block),
                "validation": f"complete PEM block ({label})",
                "risk": SEV_SCORE["CRITICAL"] + 2,
                "_raw": block,
            })
        return findings, covered

    def scan_text(self, text: str, source: str, base_line: int = 1) -> List[Dict]:
        findings: List[Dict] = []
        local_seen: Set[Tuple[str, str, str]] = set()
        pem_findings, covered = self._scan_pem_blocks(text, source)
        findings.extend(pem_findings)
        for index, line in enumerate(text.split("\n"), start=base_line):
            if not line.strip():
                continue
            findings.extend(self._scan_line(line, source, index, local_seen,
                                           covered))
        return findings

    def scan_file(self, path: str, max_bytes: int = 5 * 1024 * 1024,
                  root: Optional[str] = None) -> List[Dict]:
        data = safe_read_bytes(path, max_bytes)
        if data is None or is_binary(data):
            return []
        text = decode_text(data)
        return self.scan_text(text, source=display_path(path, root))

    def scan_archive(self, path: str, max_bytes: int = 50 * 1024 * 1024,
                     root: Optional[str] = None) -> List[Dict]:
        """Expand an archive and scan every member file inside it."""
        findings: List[Dict] = []
        members = 0
        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as zf:
                    for info in zf.infolist():
                        if members >= MAX_ARCHIVE_ENTRIES:
                            break
                        if info.is_dir() or info.file_size > MAX_ARCHIVE_ENTRY_BYTES:
                            continue
                        ext = os.path.splitext(info.filename)[1].lower()
                        if ext in SKIP_EXTS:
                            continue
                        members += 1
                        try:
                            data = zf.read(info)
                        except Exception:
                            continue
                        if is_binary(data):
                            continue
                        text = decode_text(data)
                        rel = f"{display_path(path, root)}!{info.filename}"
                        for hit in self.scan_text(text, source=rel):
                            hit["archive"] = display_path(path, root)
                            findings.append(hit)
            elif tarfile.is_tarfile(path):
                with tarfile.open(path) as tf:
                    for member in tf:
                        if members >= MAX_ARCHIVE_ENTRIES:
                            break
                        if not member.isfile():
                            continue
                        if member.size > MAX_ARCHIVE_ENTRY_BYTES:
                            continue
                        ext = os.path.splitext(member.name)[1].lower()
                        if ext in SKIP_EXTS:
                            continue
                        members += 1
                        try:
                            extracted = tf.extractfile(member)
                            if extracted is None:
                                continue
                            data = extracted.read()
                        except Exception:
                            continue
                        if is_binary(data):
                            continue
                        text = decode_text(data)
                        rel = f"{display_path(path, root)}!{member.name}"
                        for hit in self.scan_text(text, source=rel):
                            hit["archive"] = display_path(path, root)
                            findings.append(hit)
        except Exception:
            return findings
        return findings


# ═══════════════════════════════════════════════════════════════════════
# FILE WALKER + PARALLEL SCAN
# ═══════════════════════════════════════════════════════════════════════
def walk_files(root: str, follow_archives: bool = True) -> List[str]:
    out: List[str] = []
    ignore_patterns = load_path_ignores()

    if os.path.isfile(root):
        return [root]

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not path_is_ignored(dirpath, ignore_patterns)]
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            if path_is_ignored(full, ignore_patterns):
                continue
            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXTS:
                continue
            low = fname.lower()
            if low.endswith(".min.js") or low.endswith(".min.css") or low.endswith(".map"):
                continue
            if ext in ARCHIVE_EXTS:
                if follow_archives:
                    out.append(full)
                continue
            out.append(full)
    return out


def scan_files_parallel(files: List[str], scanner: SecretScanner,
                        threads: int = 8, verbose: bool = True,
                        root: Optional[str] = None,
                        follow_archives: bool = True) -> List[Dict]:
    total = len(files)
    findings: List[Dict] = []
    done = 0
    started = time.time()

    if verbose and total > 5:
        print(f"{C}>> Scanning {total} files · {threads} workers{X}\n")

    def scan_one(path: str) -> List[Dict]:
        ext = os.path.splitext(path)[1].lower()
        if follow_archives and ext in ARCHIVE_EXTS:
            return scanner.scan_archive(path, root=root)
        return scanner.scan_file(path, root=root)

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(scan_one, f): f for f in files}
        for future in as_completed(futures):
            done += 1
            try:
                findings.extend(future.result())
            except Exception:
                pass
            if verbose and total > 5 and (done % max(1, total // 10) == 0 or done == total):
                pct = done * 100 // total
                print(f"  {GR}[{done}/{total}] {pct}%{X}")

    elapsed = int(time.time() - started)
    if verbose:
        print(f"\n{G}v{X} Scanned {done} files in {elapsed}s · "
              f"{len(findings)} hits")
    return findings


# ═══════════════════════════════════════════════════════════════════════
# GIT HISTORY
# ═══════════════════════════════════════════════════════════════════════
def scan_git_history(repo_path: str, scanner: SecretScanner,
                     max_commits: int = 0, since: Optional[str] = None,
                     until: Optional[str] = None,
                     verbose: bool = True) -> Tuple[List[Dict], int]:
    cmd = ["git", "-C", repo_path, "log", "-p", "--all", "--no-color",
           "--no-ext-diff", "--unified=0", "--no-renames"]
    if max_commits > 0:
        cmd.append(f"--max-count={max_commits}")
    if since:
        cmd.append(f"--since={since}")
    if until:
        cmd.append(f"--until={until}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=900, errors="replace")
    except Exception as exc:
        if verbose:
            print(f"  {R}x{X} git log failed: {str(exc)[:100]}")
        return [], 0

    if result.returncode != 0:
        if verbose:
            print(f"  {R}x{X} git log error: {result.stderr[:120]}")
        return [], 0

    output = result.stdout
    if verbose:
        print(f"  {G}v{X} git log fetched  {GR}({human_size(len(output))}){X}")

    findings: List[Dict] = []
    seen_keys: Set[Tuple[str, str, str]] = set()

    current_commit = ""
    current_author = ""
    current_date = ""
    current_file = ""
    old_line = 0
    new_line = 0
    in_hunk = False
    commits_count = 0

    for line in output.split("\n"):
        if line.startswith("commit "):
            current_commit = line.split()[1] if len(line.split()) > 1 else ""
            current_author = ""
            current_date = ""
            in_hunk = False
            commits_count += 1
            continue
        if line.startswith("Author: "):
            current_author = line[8:]
            continue
        if line.startswith("Date: "):
            current_date = line[6:]
            continue
        if line.startswith("diff --git "):
            match = re.search(r" b/(.+)$", line)
            if match:
                current_file = match.group(1)
            in_hunk = False
            continue
        if line.startswith("Binary files "):
            continue
        if line.startswith("Subproject "):
            continue

        if line.startswith("@@"):
            match = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
            if match:
                old_line = int(match.group(1))
                new_line = int(match.group(2))
                in_hunk = True
            continue

        if not in_hunk:
            continue

        content: Optional[str] = None
        file_line = 0

        if line.startswith("+"):
            content = line[1:]
            file_line = new_line
            new_line += 1
        elif line.startswith("-"):
            content = line[1:]
            file_line = old_line
            old_line += 1
        elif line.startswith(" "):
            content = line[1:]
            file_line = new_line
            old_line += 1
            new_line += 1
        elif line.startswith("\\"):
            continue
        else:
            continue

        if content is None:
            continue

        for hit in scanner._scan_line(content, current_file, file_line, set()):
            key = (hit["file"], hit["pattern"], hit["hash"])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            hit["commit"] = current_commit[:12]
            hit["author"] = current_author.strip()
            hit["date"] = current_date.strip()
            hit["risk"] = SEV_SCORE.get(hit["severity"], 25)
            findings.append(hit)

    if verbose:
        print(f"  {G}->{X} {commits_count} commits · {len(findings)} unique hits")

    return findings, commits_count


# ═══════════════════════════════════════════════════════════════════════
# LIVE VERIFICATION  (optional - requires `requests`)
# ═══════════════════════════════════════════════════════════════════════
def _body_rejects_credential(payload: Any) -> bool:
    """True when a provider's HTTP 200 body says the credential is invalid.

    Some issuer APIs answer HTTP 200 even for an invalid credential and put the
    verdict in the JSON body -- Slack's ``auth.test`` returns
    ``{"ok": false, "error": "invalid_auth"}`` and Cloudflare's token verify
    answers ``{"success": false, ...}``. Trusting the status code alone would
    report every syntactically valid but dead token as LIVE, so the body is
    inspected before a 200 counts as acceptance.
    """
    if not isinstance(payload, dict):
        return False
    if payload.get("ok") is False:
        return True
    if payload.get("success") is False:
        return True
    result = payload.get("result")
    if isinstance(result, dict):
        if str(result.get("status", "")).lower() == "invalid":
            return True
        if result.get("success") is False:
            return True
    return False


VERIFIER: Dict[str, Dict[str, Any]] = {
    "GitHub PAT (classic)": {"method": "GET", "url": "https://api.github.com/user",
                             "headers": {"Authorization": "Bearer {v}"}},
    "GitHub Fine-Grained PAT": {"method": "GET", "url": "https://api.github.com/user",
                                "headers": {"Authorization": "Bearer {v}"}},
    "GitHub OAuth Token": {"method": "GET", "url": "https://api.github.com/user",
                           "headers": {"Authorization": "Bearer {v}"}},
    "Slack Bot Token": {"method": "GET", "url": "https://slack.com/api/auth.test",
                        "headers": {"Authorization": "Bearer {v}"},
                        "body_check": True},
    "Slack User Token": {"method": "GET", "url": "https://slack.com/api/auth.test",
                         "headers": {"Authorization": "Bearer {v}"},
                         "body_check": True},
    "SendGrid API Key": {"method": "GET", "url": "https://api.sendgrid.com/v3/scopes",
                         "headers": {"Authorization": "Bearer {v}"}},
    "Telegram Bot Token": {"method": "GET", "url": "https://api.telegram.org/bot{v}/getMe"},
    "NPM Token": {"method": "GET", "url": "https://registry.npmjs.org/-/npm/v1/tokens",
                  "headers": {"Authorization": "Bearer {v}"}},
    "DigitalOcean PAT": {"method": "GET", "url": "https://api.digitalocean.com/v2/account",
                         "headers": {"Authorization": "Bearer {v}"}},
    "Cloudflare API Token": {"method": "GET",
                             "url": "https://api.cloudflare.com/client/v4/user/tokens/verify",
                             "headers": {"Authorization": "Bearer {v}"}},
    "OpenAI API Key": {"method": "GET", "url": "https://api.openai.com/v1/models",
                       "headers": {"Authorization": "Bearer {v}"}},
    "Anthropic API Key": {"method": "GET", "url": "https://api.anthropic.com/v1/models",
                          "headers": {"x-api-key": "{v}", "anthropic-version": "2023-06-01"}},
    "Notion API Token": {"method": "GET", "url": "https://api.notion.com/v1/users/me",
                         "headers": {"Authorization": "Bearer {v}",
                                     "Notion-Version": "2022-06-28"}},
    "Postman API Key": {"method": "GET", "url": "https://api.getpostman.com/environments",
                        "headers": {"X-Api-Key": "{v}"}},
    "Airtable PAT": {"method": "GET", "url": "https://api.airtable.com/v0/meta/bases",
                     "headers": {"Authorization": "Bearer {v}"}},
    "Vercel Token": {"method": "GET", "url": "https://api.vercel.com/v2/user",
                     "headers": {"Authorization": "Bearer {v}"}},
    "Square Access Token": {"method": "GET", "url": "https://connect.squareup.com/v2/locations",
                            "headers": {"Authorization": "Bearer {v}"}},
    "Netlify Auth Token": {"method": "GET", "url": "https://api.netlify.com/api/v1/user",
                           "headers": {"Authorization": "Bearer {v}"}},
    "Datadog API Key": {"method": "GET", "url": "https://api.datadoghq.com/api/v1/validate",
                        "headers": {"DD-API-KEY": "{v}", "DD-APPLICATION-KEY": "x"}},
    "Stripe Live Secret Key": {"method": "GET", "url": "https://api.stripe.com/v1/charges?limit=1",
                               "headers": {"Authorization": "Bearer {v}"}},
    "Hugging Face Token": {"method": "GET", "url": "https://huggingface.co/api/whoami-v2",
                           "headers": {"Authorization": "Bearer {v}"}},
}


def verify_secret(pattern: str, value: str, timeout: int = 10) -> Tuple[str, str]:
    """Live-check a credential against its issuer.

    Returns (status, detail) where status is LIVE / DEAD / UNKNOWN / SKIPPED.
    Only the credential's own provider is contacted.
    """
    spec = VERIFIER.get(pattern)
    if spec is None:
        return "SKIPPED", "no live check available for this pattern"
    try:
        import requests                     # noqa: WPS433 (optional dependency)
    except ImportError:
        return "SKIPPED", "install 'requests' to enable live verification"

    url = spec["url"].replace("{v}", value)
    headers = {k: v.replace("{v}", value) for k, v in spec.get("headers", {}).items()}
    try:
        response = requests.request(spec["method"], url, headers=headers, timeout=timeout)
    except Exception as exc:
        return "UNKNOWN", f"network error: {str(exc)[:80]}"

    code = response.status_code
    if code in (200, 201):
        if spec.get("body_check"):
            try:
                payload = response.json()
            except Exception:
                payload = None
            if _body_rejects_credential(payload):
                return ("DEAD", "provider rejected the credential "
                               "(HTTP 200 with an error body)")
        return "LIVE", f"provider accepted the credential (HTTP {code})"
    if code in (401, 403):
        return "DEAD", f"provider rejected the credential (HTTP {code})"
    if code == 429:
        return "LIVE", "provider rate-limited but recognises the credential"
    return "UNKNOWN", f"unexpected HTTP {code}"


def verify_findings(findings: List[Dict], timeout: int = 10,
                    verbose: bool = True) -> List[Dict]:
    """Verify every finding that still carries its raw value.

    One credential is often exposed on many pages of the same site, and a
    bulk URL scan can surface the same secret thousands of times. Each
    distinct secret is therefore checked against its issuer once, and that
    verdict is shared by every finding carrying it.
    """
    verified: List[Dict] = []
    verdicts: Dict[Tuple[str, str], Tuple[str, str]] = {}
    for finding in findings:
        raw = finding.get("_raw")
        if not raw:
            verified.append({**finding, "live_status": "SKIPPED",
                             "live_detail": "raw value not retained (redacted scan)"})
            continue
        key = (finding["pattern"], finding.get("hash", ""))
        if key not in verdicts:
            status, detail = verify_secret(finding["pattern"], raw, timeout=timeout)
            verdicts[key] = (status, detail)
            if verbose:
                colour = {"LIVE": R + B, "DEAD": GR, "UNKNOWN": Y,
                          "SKIPPED": GR}.get(status, Y)
                print(f"  {colour}{status:<8}{X} {finding['pattern']}  "
                      f"{GR}{detail}{X}")
        status, detail = verdicts[key]
        verified.append({**finding, "live_status": status,
                         "live_detail": detail})
    return verified


# ═══════════════════════════════════════════════════════════════════════
# WEB RECON  (single-site scanning - standard library only)
# ═══════════════════════════════════════════════════════════════════════
DEFAULT_USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/124.0.0.0 Safari/537.36")

# Paths that must never be readable from the public internet. A 200 here is
# a finding on its own, and the body is scanned for credentials as well.
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.DS_Store",
    "/config.json",
    "/package.json",
]

# Public files worth reading for reconnaissance.
INFO_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
]

RECON_PATHS = SENSITIVE_PATHS + INFO_PATHS

TEXTUAL_HINTS = ("text/", "javascript", "json", "xml", "xhtml", "svg")


def is_text_payload(content_type: str, raw: bytes) -> bool:
    """True when a response body is worth scanning as text."""
    ctype = (content_type or "").lower().split(";")[0].strip()
    if ctype.startswith("image/") or ctype in (
            "application/octet-stream", "application/zip", "application/gzip",
            "application/x-gzip", "application/pdf", "font/woff",
            "font/woff2", "application/x-font-ttf"):
        return False
    if ctype and not any(hint in ctype for hint in TEXTUAL_HINTS):
        return False
    return b"\x00" not in raw[:2048]


def http_get(url: str, timeout: int = 15,
             headers: Optional[Dict[str, str]] = None,
             max_bytes: int = 5 * 1024 * 1024) -> Tuple[int, str, str, str]:
    """GET a URL using the standard library only.

    Returns (status, content_type, body_text, final_url). A failed request
    comes back as status 0 with an empty body -- the caller decides what that
    means in its context.
    """
    request_headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers, method="GET")
    status, ctype, raw, final_url = 0, "", b"", url
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", None) or response.getcode() or 0
            ctype = response.headers.get("Content-Type", "") or ""
            final_url = response.geturl()
            raw = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        status = exc.code
        ctype = (exc.headers.get("Content-Type", "") if exc.headers else "") or ""
        try:
            raw = exc.read(max_bytes + 1)
        except Exception:
            raw = b""
    except Exception:
        return 0, "", "", url
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    text = decode_text(raw) if raw and is_text_payload(ctype, raw) else ""
    return status, ctype, text, final_url


class _HtmlCollector(HTMLParser):
    """Collects script/style references, inline scripts and links from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: List[str] = []
        self.styles: List[str] = []
        self.links: List[str] = []
        self.inline: List[str] = []
        self._in_script = False
        self._buffer: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attributes = {key.lower(): (value or "") for key, value in attrs}
        if tag == "script":
            src = attributes.get("src", "").strip()
            if src:
                self.scripts.append(src)
            else:
                self._in_script = True
                self._buffer = []
        elif tag == "link":
            rel = attributes.get("rel", "").lower()
            href = attributes.get("href", "").strip()
            if href and ("stylesheet" in rel or "preload" in rel):
                self.styles.append(href)
        elif tag == "a":
            href = attributes.get("href", "").strip()
            if href:
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            body = "".join(self._buffer)
            if body.strip():
                self.inline.append(body)
            self._in_script = False
            self._buffer = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._buffer.append(data)


def parse_html(text: str, base_url: str) -> Dict[str, List[str]]:
    """Extract asset and link references from an HTML document."""
    collector = _HtmlCollector()
    try:
        collector.feed(text)
        collector.close()
    except Exception:
        pass

    def resolve(refs: List[str]) -> List[str]:
        resolved: List[str] = []
        seen: Set[str] = set()
        for ref in refs:
            if not ref or ref.startswith(("data:", "javascript:", "#", "mailto:")):
                continue
            url = urllib.parse.urljoin(base_url, ref)
            if url in seen:
                continue
            seen.add(url)
            resolved.append(url)
        return resolved

    return {
        "scripts": resolve(collector.scripts),
        "styles": resolve(collector.styles),
        "links": resolve(collector.links),
        "inline": collector.inline,
    }


# ── URL lists ─────────────────────────────────────────────────────────
# A .txt file holding thousands of URLs is a list of *targets* to visit,
# not a file whose text happens to contain secrets. Scanning the text alone
# only ever reports credentials that happen to sit inside the URL strings,
# which is why a 9000-URL list used to come back with a few dozen hits
# instead of the hundreds really exposed on those sites.
URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)

# A file has to look overwhelmingly like a list before it is treated as one,
# so an ordinary source file that happens to mention a few links keeps its
# normal file-scanning behaviour.
URL_LIST_MIN_LINES = 5
URL_LIST_MIN_RATIO = 0.6

_URL_TRAILING = ".,;:!?\"'<>"
_URL_CLOSERS = {")": "(", "]": "[", "}": "{"}


def _clean_url(url: str) -> str:
    """Trim punctuation that belongs to the surrounding text, not the URL."""
    url = url.rstrip(_URL_TRAILING)
    changed = True
    while changed and url:
        changed = False
        last = url[-1]
        opener = _URL_CLOSERS.get(last)
        if opener and url.count(last) > url.count(opener):
            url = url[:-1]
            changed = True
    return url


def extract_urls(text: str) -> List[str]:
    """Return every http(s) URL in `text`, in order of appearance.

    Blank lines and `#` comments are ignored. A URL sitting inside a longer
    line (a CSV cell, a log line) is picked up as well.
    """
    urls: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for match in URL_RE.finditer(stripped):
            url = _clean_url(match.group(0))
            if url:
                urls.append(url)
    return urls


def looks_like_url_list(text: str) -> bool:
    """True when `text` is predominantly a list of http(s) URLs."""
    meaningful = [line.strip() for line in text.splitlines()]
    meaningful = [line for line in meaningful
                  if line and not line.startswith("#")]
    if not meaningful:
        return False
    url_lines = sum(1 for line in meaningful if URL_RE.search(line))
    if url_lines < URL_LIST_MIN_LINES:
        return False
    return (url_lines / len(meaningful)) >= URL_LIST_MIN_RATIO


def _read_text_file(path: str, max_bytes: int) -> str:
    """Read a file as text, or return an empty string if it is not text."""
    data = safe_read_bytes(path, max_bytes)
    if data is None or is_binary(data):
        return ""
    return decode_text(data)


def fetch_target(url: str, scanner: SecretScanner, crawl: int = 0,
                 max_assets: int = 25, timeout: int = 15,
                 headers: Optional[Dict[str, str]] = None,
                 user_agent: Optional[str] = None, recon: bool = True,
                 verbose: bool = False,
                 max_bytes: int = 5 * 1024 * 1024) -> Dict[str, Any]:
    """Fetch one URL and scan everything that comes back.

    Reads the page, its inline scripts and its JS/CSS assets, optionally
    crawls same-host pages and probes sensitive paths. Read-only GETs only.

    Returns the findings, the sources that were read and the recon rows.
    Never raises: a failed request comes back as status 0.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        if verbose:
            print(f"  {R}!{X} not a valid http(s) URL: {url}")
        return {"url": url, "status": 0, "findings": [], "sources": [],
                "recon": [], "ok": False, "invalid": True, "error": "invalid url"}

    host = parsed.netloc.lower()

    request_headers = dict(headers or {})
    if user_agent:
        request_headers["User-Agent"] = user_agent

    findings: List[Dict] = []
    sources: List[str] = []
    recon_rows: List[Dict] = []
    visited: Set[str] = set()
    queue: List[str] = [url]
    asset_budget = max_assets
    pages = 0

    while queue and pages <= crawl:
        page_url = queue.pop(0)
        if page_url in visited:
            continue
        visited.add(page_url)
        status, _ctype, text, final_url = http_get(
            page_url, timeout=timeout, headers=request_headers,
            max_bytes=max_bytes)
        pages += 1
        if status == 0:
            if verbose:
                print(f"  {Y}!{X} {page_url} {GR}· request failed{X}")
            continue
        if status != 200 or not text:
            if verbose:
                print(f"  {Y}!{X} {page_url} {GR}· HTTP {status}{X}")
            continue
        if verbose:
            print(f"  {G}->{X} {final_url} {GR}({len(text)} bytes){X}")
        sources.append(final_url)
        findings.extend(scanner.scan_text(text, source=final_url))

        parts = parse_html(text, final_url)

        for index, body in enumerate(parts["inline"], start=1):
            label = f"{final_url}#inline-{index}"
            findings.extend(scanner.scan_text(body, source=label))

        for asset_url in parts["scripts"] + parts["styles"]:
            if asset_budget <= 0:
                if verbose:
                    print(f"  {Y}!{X} asset budget reached ({max_assets})")
                break
            asset_budget -= 1
            a_status, _a_ctype, a_text, a_final = http_get(
                asset_url, timeout=timeout, headers=request_headers,
                max_bytes=max_bytes)
            if a_status != 200 or not a_text:
                if verbose:
                    print(f"  {Y}!{X} {asset_url} {GR}· HTTP {a_status}{X}")
                continue
            if verbose:
                print(f"  {G}->{X} {a_final} "
                      f"{GR}(asset, {len(a_text)} bytes){X}")
            sources.append(a_final)
            findings.extend(scanner.scan_text(a_text, source=a_final))

        if crawl:
            for link in parts["links"]:
                if urllib.parse.urlparse(link).netloc.lower() != host:
                    continue
                if link not in visited and link not in queue:
                    queue.append(link)

    # ── sensitive-path recon ────────────────────────────────────────────
    if recon:
        if verbose:
            print(f"\n  {C}>>{X} recon {GR}· probing {len(RECON_PATHS)} "
                  f"sensitive paths{X}")
        for path in RECON_PATHS:
            target_url = urllib.parse.urljoin(url, path)
            r_status, _r_ctype, r_text, r_final = http_get(
                target_url, timeout=timeout, headers=request_headers,
                max_bytes=max_bytes)
            row = {
                "path": path,
                "url": target_url,
                "status": r_status,
                "sensitive": path in SENSITIVE_PATHS,
                "exposed": False,
                "secrets": 0,
            }
            if r_status == 200 and r_text:
                row["exposed"] = path in SENSITIVE_PATHS
                hits = scanner.scan_text(r_text, source=r_final)
                row["secrets"] = len(hits)
                findings.extend(hits)
                sources.append(r_final)
            recon_rows.append(row)
            if verbose:
                if row["exposed"]:
                    mark = f"{R}{B}EXPOSED{X}"
                else:
                    mark = f"{GR}HTTP {r_status}{X}"
                extra = (f" {R}({row['secrets']} secrets){X}"
                         if row["secrets"] else "")
                print(f"    {mark} {path}{extra}")

    return {"url": url, "status": status, "findings": findings,
            "sources": sources, "recon": recon_rows,
            "ok": bool(sources), "invalid": False, "error": ""}


def scan_url_list(urls: List[str], scanner: SecretScanner, threads: int = 20,
                  timeout: int = 10, crawl: int = 0, max_assets: int = 25,
                  headers: Optional[Dict[str, str]] = None,
                  user_agent: Optional[str] = None, recon: bool = False,
                  verbose: bool = True,
                  max_bytes: int = 5 * 1024 * 1024) -> Dict[str, Any]:
    """Scan a list of URLs concurrently and merge every finding.

    Duplicate URLs are visited once. One unreachable target can never hide
    the others: every target is visited and counted on its own.
    """
    unique: List[str] = []
    seen: Set[str] = set()
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique.append(url)

    total = len(unique)
    findings: List[Dict] = []
    sources: List[str] = []
    recon_rows: List[Dict] = []
    ok = 0
    failed = 0
    done = 0
    started = time.time()
    step = max(1, total // 10)

    def worker(url: str) -> Dict[str, Any]:
        try:
            return fetch_target(url, scanner, crawl=crawl,
                                max_assets=max_assets, timeout=timeout,
                                headers=headers, user_agent=user_agent,
                                recon=recon, verbose=False,
                                max_bytes=max_bytes)
        except Exception as exc:
            return {"url": url, "status": 0, "findings": [], "sources": [],
                    "recon": [], "ok": False, "invalid": False,
                    "error": type(exc).__name__}

    if verbose and total:
        print(f"{C}>> Scanning {total} target(s) · {threads} workers{X}\n")

    if total:
        with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
            futures = [pool.submit(worker, url) for url in unique]
            for future in as_completed(futures):
                done += 1
                try:
                    result = future.result()
                except Exception:
                    result = {"ok": False, "findings": [], "sources": [],
                              "recon": []}
                if result.get("ok"):
                    ok += 1
                else:
                    failed += 1
                findings.extend(result.get("findings", []))
                sources.extend(result.get("sources", []))
                recon_rows.extend(result.get("recon", []))
                if verbose and total > 5 and (done % step == 0 or done == total):
                    pct = done * 100 // total
                    print(f"  {GR}[{done}/{total}] {pct}% · "
                          f"{len(findings)} findings · {failed} unreachable{X}")

    return {
        "findings": findings,
        "sources": sources,
        "recon": recon_rows,
        "targets_total": len(urls),
        "targets_unique": total,
        "targets_ok": ok,
        "targets_failed": failed,
        "duration_ms": int((time.time() - started) * 1000),
    }


def scan_url(url: str, crawl: int = 0, max_assets: int = 25, timeout: int = 15,
             user_agent: Optional[str] = None,
             headers: Optional[Dict[str, str]] = None, recon: bool = True,
             only: Optional[str] = None, min_severity: str = "LOW",
             no_entropy: bool = False, no_redact: bool = False,
             allowlist: Optional[Set[str]] = None, min_entropy: float = 4.2,
             decode_encoded: bool = True, name: Optional[str] = None,
             verbose: bool = True,
             max_bytes: int = 5 * 1024 * 1024) -> Optional[Dict]:
    """Scan a single website for exposed credentials.

    Fetches the page, scans the HTML and every inline script, downloads the
    referenced JavaScript/CSS assets, optionally crawls same-host pages, and
    probes sensitive paths. Read-only GET requests only.
    """
    started = now_iso()
    begin = time.time()

    only_cats = ({x.strip().lower() for x in only.split(",") if x.strip()}
                 if only else None)
    scanner = SecretScanner(
        redact_mode=not no_redact,
        entropy=not no_entropy,
        allowlist=allowlist or set(),
        only_cats=only_cats,
        min_severity=min_severity,
        decode_encoded=decode_encoded,
        min_entropy=min_entropy,
    )

    result = fetch_target(url, scanner, crawl=crawl, max_assets=max_assets,
                          timeout=timeout, headers=headers,
                          user_agent=user_agent, recon=recon,
                          verbose=verbose, max_bytes=max_bytes)
    if result.get("invalid"):
        return None

    findings = result["findings"]
    sources = result["sources"]
    recon_rows = result["recon"]

    findings.sort(key=lambda f: (-f.get("risk", 0), f.get("file", ""),
                                 f.get("line", 0)))
    report_name = name or f"url_{stamp()}"
    duration = int((time.time() - begin) * 1000)

    report = {
        "name": report_name,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "author": AUTHOR_NAME,
        "target": url,
        "kind": "url",
        "started": started,
        "finished": now_iso(),
        "duration_ms": duration,
        "history": False,
        "files_scanned": len(sources),
        "commits_scanned": 0,
        "options": {
            "crawl": crawl,
            "max_assets": max_assets,
            "timeout": timeout,
            "recon": recon,
            "only": only,
            "min_severity": min_severity,
            "no_entropy": no_entropy,
            "no_redact": no_redact,
            "min_entropy": min_entropy,
        },
        "findings": findings,
        "summary": _build_summary(findings),
        "recon": recon_rows,
        "sources": sources,
    }

    path = _save_report(report)
    if verbose:
        print(f"\n  {G}v{X} Saved -> {B}{path}{X}")
    return report


def cmd_url(args: argparse.Namespace) -> Optional[Dict]:
    """Entry point for `secret_sniper.py url <URL>`."""
    allowlist = load_allowlist()
    headers: Dict[str, str] = {}
    for raw in (args.header or []):
        if ":" in raw:
            key, _, value = raw.partition(":")
            headers[key.strip()] = value.strip()

    report = scan_url(
        url=args.url,
        crawl=args.crawl,
        max_assets=args.max_assets,
        timeout=args.timeout,
        user_agent=args.user_agent,
        headers=headers,
        recon=not args.no_recon,
        only=args.only,
        min_severity=args.min_severity,
        no_entropy=args.no_entropy,
        no_redact=args.no_redact,
        allowlist=allowlist,
        min_entropy=args.min_entropy,
        name=args.name,
        verbose=not args.quiet,
    )
    if not report:
        footer()
        return None

    if args.verify:
        print(f"\n{C}>> Live verification "
              f"(contacting each credential's provider){X}")
        report["findings"] = verify_findings(report["findings"],
                                             verbose=not args.quiet)
        report["summary"] = _build_summary(report["findings"])
        _save_report(report)

    render_report(report, show_all=not args.quiet)

    if args.export:
        do_export(report, args.export, args.out)

    footer()

    if args.fail_on:
        threshold = SEV_ORDER.get(args.fail_on.upper(), 3)
        if any(SEV_ORDER.get(f["severity"], 99) <= threshold
               for f in report["findings"]):
            sys.exit(1)
    return report


def cmd_urls(args: argparse.Namespace) -> Optional[Dict]:
    """Entry point for `secret_sniper.py urls <LIST>`.

    Every URL in the list is visited and scanned, exactly as `url` would
    scan it on its own, but concurrently. The list file itself is scanned
    too, so a credential pasted next to a URL is still caught.
    """
    allowlist = load_allowlist()

    if not os.path.isfile(args.list_file):
        print(f"{R}Not found: {args.list_file}{X}")
        footer()
        return None

    text = _read_text_file(args.list_file, 64 * 1024 * 1024)
    urls = extract_urls(text)
    if not urls:
        print(f"{Y}No http(s) URLs found in {args.list_file}{X}")
        footer()
        return None
    if args.max_urls and len(urls) > args.max_urls:
        urls = urls[:args.max_urls]

    only_cats = ({x.strip().lower() for x in args.only.split(",") if x.strip()}
                 if args.only else None)
    scanner = SecretScanner(
        redact_mode=not args.no_redact,
        entropy=not args.no_entropy,
        allowlist=allowlist,
        only_cats=only_cats,
        min_severity=args.min_severity,
        decode_encoded=True,
        min_entropy=args.min_entropy,
    )

    started = now_iso()
    begin = time.time()

    bulk = scan_url_list(urls, scanner, threads=args.threads,
                         timeout=args.timeout, crawl=args.crawl,
                         max_assets=args.max_assets, recon=args.recon,
                         verbose=not args.quiet)

    findings = scanner.scan_text(text, source=args.list_file)
    findings.extend(bulk["findings"])
    findings.sort(key=lambda f: (-f.get("risk", 0), f.get("file", ""),
                                 f.get("line", 0)))

    report_name = args.name or f"urls_{stamp()}"
    report = {
        "name": report_name,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "author": AUTHOR_NAME,
        "target": args.list_file,
        "kind": "url-list",
        "started": started,
        "finished": now_iso(),
        "duration_ms": int((time.time() - begin) * 1000),
        "history": False,
        "files_scanned": len(bulk["sources"]) + 1,
        "commits_scanned": 0,
        "options": {
            "threads": args.threads,
            "timeout": args.timeout,
            "crawl": args.crawl,
            "max_assets": args.max_assets,
            "recon": args.recon,
            "only": args.only,
            "min_severity": args.min_severity,
            "no_entropy": args.no_entropy,
            "no_redact": args.no_redact,
            "min_entropy": args.min_entropy,
            "url_list": "on",
            "max_urls": args.max_urls,
        },
        "targets_total": bulk["targets_total"],
        "targets_unique": bulk["targets_unique"],
        "targets_ok": bulk["targets_ok"],
        "targets_failed": bulk["targets_failed"],
        "findings": findings,
        "summary": _build_summary(findings),
        "recon": bulk["recon"],
        "sources": bulk["sources"],
    }

    path = _save_report(report)
    if not args.quiet:
        print(f"\n  {G}v{X} Saved -> {B}{path}{X}")

    if args.verify:
        print(f"\n{C}>> Live verification "
              f"(contacting each credential's provider){X}")
        report["findings"] = verify_findings(report["findings"],
                                             verbose=not args.quiet)
        report["summary"] = _build_summary(report["findings"])
        _save_report(report)

    render_report(report, show_all=not args.quiet)

    if args.export:
        do_export(report, args.export, args.out)

    footer()

    if args.fail_on:
        threshold = SEV_ORDER.get(args.fail_on.upper(), 3)
        if any(SEV_ORDER.get(f["severity"], 99) <= threshold
               for f in report["findings"]):
            sys.exit(1)
    return report


# ═══════════════════════════════════════════════════════════════════════
# REPORT BUILD
# ═══════════════════════════════════════════════════════════════════════
def _build_summary(findings: List[Dict]) -> Dict:
    by_sev: Dict[str, int] = {}
    by_cat: Dict[str, int] = {}
    by_conf: Dict[str, int] = {}
    for finding in findings:
        by_sev[finding["severity"]] = by_sev.get(finding["severity"], 0) + 1
        by_cat[finding["category"]] = by_cat.get(finding["category"], 0) + 1
        by_conf[finding["confidence"]] = by_conf.get(finding["confidence"], 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_category": by_cat,
        "by_confidence": by_conf,
        "risk_score": sum(finding.get("risk", 0) for finding in findings),
    }


def _save_report(report: Dict) -> str:
    """Persist a report, stripping raw secret values before they hit disk."""
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, f"{report['name']}.json")
    tmp = path + ".tmp"
    safe = {k: v for k, v in report.items() if k != "findings"}
    safe["findings"] = [
        {k: v for k, v in finding.items() if k != "_raw"}
        for finding in report.get("findings", [])
    ]
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(safe, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    return path


def load_report(name: str) -> Optional[Dict]:
    path = os.path.join(DATA_DIR, f"{name}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════
# EXPORTERS
# ═══════════════════════════════════════════════════════════════════════
def export_json(report: Dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def export_csv(report: Dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["pattern", "severity", "confidence", "category", "file",
                     "line", "match", "hash", "risk", "validation",
                     "live_status", "commit", "author", "date"])
    for finding in report.get("findings", []):
        writer.writerow([
            finding.get("pattern", ""), finding.get("severity", ""),
            finding.get("confidence", ""), finding.get("category", ""),
            finding.get("file", ""), finding.get("line", ""),
            finding.get("match", ""), finding.get("hash", ""),
            finding.get("risk", ""), finding.get("validation", ""),
            finding.get("live_status", ""), finding.get("commit", ""),
            finding.get("author", ""), finding.get("date", ""),
        ])
    return buf.getvalue()


def sarif_level(sev: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
            "LOW": "note", "INFO": "note"}.get(sev.upper(), "note")


def rule_id(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def export_sarif(report: Dict) -> str:
    rules: Dict[str, Dict] = {}
    for spec in PATTERNS:
        rid = rule_id(spec["name"])
        rules[rid] = {
            "id": rid,
            "name": spec["name"],
            "shortDescription": {"text": spec["name"]},
            "fullDescription": {"text": spec.get("desc", f"Possible {spec['name']} detected.")},
            "defaultConfiguration": {"level": sarif_level(spec["severity"])},
            "properties": {
                "tags": [spec["category"], "security", "secret"],
                "severity": spec["severity"],
                "confidence": spec["confidence"],
            },
        }

    results = []
    for finding in report.get("findings", []):
        results.append({
            "ruleId": rule_id(finding["pattern"]),
            "level": sarif_level(finding["severity"]),
            "message": {"text": f"{finding['pattern']} detected in {finding['file']}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding["file"]},
                    "region": {"startLine": max(1, int(finding.get("line") or 1))},
                }
            }],
            "properties": {
                "severity": finding["severity"],
                "confidence": finding["confidence"],
                "match": finding["match"],
                "hash": finding["hash"],
            },
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": GITHUB_LINK,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {
                "scan_target": report.get("target", ""),
                "scan_started": report.get("started", ""),
                "author": AUTHOR_NAME,
            },
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def export_html(report: Dict) -> str:
    """Self-contained HTML report (no external assets)."""
    findings = report.get("findings", [])
    summary = report.get("summary", {})

    def esc(text: Any) -> str:
        return (str(text).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    rows = []
    for finding in findings:
        colour = {"CRITICAL": "#ff4d4f", "HIGH": "#ff7a45",
                  "MEDIUM": "#faad14", "LOW": "#36cfc9",
                  "INFO": "#8c8c8c"}.get(finding["severity"], "#d9d9d9")
        live = finding.get("live_status", "")
        live_html = f'<span class="tag">{esc(live)}</span>' if live else ""
        rows.append(
            f'<tr><td><span class="sev" style="background:{colour}">'
            f'{esc(finding["severity"])}</span></td>'
            f'<td>{esc(finding["pattern"])}</td>'
            f'<td class="mono">{esc(finding["file"])}:{esc(finding.get("line", ""))}</td>'
            f'<td class="mono">{esc(finding["match"])}</td>'
            f'<td>{esc(finding.get("confidence", ""))}{live_html}</td></tr>'
        )

    sev_cards = "".join(
        f'<div class="card"><div class="num">{esc(summary.get("by_severity", {}).get(s, 0))}</div>'
        f'<div class="lbl">{s}</div></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(TOOL_NAME)} - {esc(report.get('name', 'scan'))}</title>
<style>
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; padding:32px; background:#0d1117; color:#e6edf3;
  font:14px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; }}
h1 {{ margin:0 0 4px; font-size:22px; }}
.sub {{ color:#8b949e; margin-bottom:24px; }}
.cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:24px; }}
.card {{ background:#161b22; border:1px solid #30363d; border-radius:10px;
  padding:14px 20px; min-width:110px; }}
.num {{ font-size:26px; font-weight:700; }}
.lbl {{ color:#8b949e; font-size:11px; letter-spacing:.06em; text-transform:uppercase; }}
table {{ width:100%; border-collapse:collapse; background:#161b22;
  border:1px solid #30363d; border-radius:10px; overflow:hidden; }}
th,td {{ padding:9px 12px; text-align:left; border-bottom:1px solid #21262d;
  vertical-align:top; font-size:13px; }}
th {{ background:#1c2128; color:#8b949e; font-weight:600; text-transform:uppercase;
  font-size:11px; letter-spacing:.05em; }}
tr:last-child td {{ border-bottom:none; }}
.mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
.sev {{ color:#0d1117; padding:2px 8px; border-radius:5px; font-weight:700;
  font-size:10px; letter-spacing:.04em; }}
.tag {{ display:inline-block; margin-left:6px; padding:1px 7px; border-radius:5px;
  background:#30363d; color:#e6edf3; font-size:10px; }}
footer {{ margin-top:28px; color:#8b949e; font-size:12px; }}
a {{ color:#58a6ff; }}
</style></head><body>
<h1>{esc(TOOL_NAME)}</h1>
<div class="sub">Target <b>{esc(report.get('target', ''))}</b> · started {esc(report.get('started', ''))}
 · {esc(report.get('files_scanned', 0))} files · {esc(report.get('duration_ms', 0))} ms</div>
<div class="cards">{sev_cards}</div>
<table><thead><tr><th>Severity</th><th>Pattern</th><th>Location</th>
<th>Value</th><th>Confidence</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="5">No secrets detected.</td></tr>'}</tbody></table>
<footer>{esc(TOOL_NAME)} v{esc(TOOL_VERSION)} · {esc(AUTHOR_NAME)} ({esc(AUTHOR_HANDLE)})
 · <a href="{esc(GITHUB_LINK)}">{esc(GITHUB_LINK)}</a>
 · Detection only. Scan only assets you own or are authorised to audit.</footer>
</body></html>"""


def do_export(report: Dict, fmt: str, out: Optional[str]) -> Optional[str]:
    fmt = fmt.lower()
    if fmt == "json":
        content, ext = export_json(report), ".json"
    elif fmt == "csv":
        content, ext = export_csv(report), ".csv"
    elif fmt == "sarif":
        content, ext = export_sarif(report), ".sarif.json"
    elif fmt == "html":
        content, ext = export_html(report), ".html"
    else:
        print(f"{R}Unknown format: {fmt}{X}")
        return None
    if not out:
        base = os.path.basename(report.get("name", "scan"))
        out = f"{base}{ext}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"{G}v{X} Exported {B}{fmt}{X} -> {B}{out}{X}")
    return out


# ═══════════════════════════════════════════════════════════════════════
# RENDERERS
# ═══════════════════════════════════════════════════════════════════════
def banner() -> None:
    title = TOOL_NAME.upper()
    sub = "Leaked credential detection & live verification"
    width = 64
    print(f"{R}+{'-' * width}+{X}")
    print(f"{R}|{X} {B}{W}{title}{X}")
    print(f"{R}|{X} {GR}{sub}{X}")
    print(f"{R}|{X}")
    print(f"{R}|{X} {W}by {X}{B}{AUTHOR_NAME}{X} {GR}({AUTHOR_ALIAS}){X}")
    print(f"{R}|{X} {W}Telegram : {X}{C}{TELEGRAM_LINK}{X}")
    print(f"{R}|{X} {W}GitHub   : {X}{C}{REPO_LINK}{X}")
    print(f"{R}|{X} {W}Profile  : {X}{C}{GITHUB_LINK}{X}")
    print(f"{R}|{X} {W}Version  : {X}{GR}v{TOOL_VERSION}{X}")
    print(f"{R}+{'-' * width}+{X}")


# ═══════════════════════════════════════════════════════════════════════
# HELP
# ═══════════════════════════════════════════════════════════════════════
ASCII_FONT: Dict[str, List[str]] = {
    "S": ["███████", "██     ", "███████", "     ██", "███████"],
    "E": ["███████", "██     ", "█████  ", "██     ", "███████"],
    "C": ["███████", "██     ", "██     ", "██     ", "███████"],
    "R": ["███████", "██  ██", "███████", "██  ██", "██   ██"],
    "T": ["███████", "  ██  ", "  ██  ", "  ██  ", "  ██  "],
    "N": ["██   ██", "███  ██", "████ ██", "██ ███", "██  ██"],
    "I": ["███████", "  ██  ", "  ██  ", "  ██  ", "███████"],
    "P": ["███████", "██  ██", "███████", "██     ", "██     "],
}

HELP_TOPICS: Dict[str, Dict[str, str]] = {
    "scan": {
        "usage": "scan TARGET",
        "summary": "Scan a file, folder, archive, git repository or stdin.",
        "detail": ("TARGET is a file, a directory, a .zip/.tar archive, a git\n"
                   "      repository, or '-' to read from standard input.\n"
                   "      A file that is mostly http(s) URLs is treated as a list\n"
                   "      of targets: every URL in it is fetched and scanned.\n"
                   "      --history   also walks every commit in the history.\n"
                   "      --baseline  hides secrets already seen in a saved scan.\n"
                   "      --verify    live-checks each credential with its issuer."),
        "options": ("--history --baseline --only --min-severity --min-entropy\n"
                    "      --no-entropy --no-redact --no-decode --no-archives\n"
                    "      --max-size-mb --max-commits --since --until --threads\n"
                    "      --url-list --no-url-list --timeout --crawl --max-assets\n"
                    "      --recon --max-urls --verify --fail-on\n"
                    "      -e/--export -o/--out --name -q"),
    },
    "urls": {
        "usage": "urls LIST",
        "summary": "Scan every URL listed in a file, concurrently.",
        "detail": ("LIST holds one http(s) URL per line. Each target is\n"
                   "      fetched and scanned exactly the way `url` scans one\n"
                   "      site: page, inline scripts, JS/CSS assets and an\n"
                   "      optional crawl. Thousands of targets are visited in\n"
                   "      parallel and every one of them is counted, whether\n"
                   "      it answered or not.\n"
                   "      --recon    probe sensitive paths on every target."),
        "options": ("--threads --timeout --crawl --max-assets --recon\n"
                    "      --max-urls --only --min-severity --min-entropy\n"
                    "      --no-entropy --no-redact --verify --fail-on\n"
                    "      -e/--export -o/--out --name -q"),
    },
    "url": {
        "usage": "url URL",
        "summary": "Scan a single website for exposed credentials.",
        "detail": ("Fetches the page, scans the HTML and every inline script,\n"
                   "      downloads the referenced JavaScript/CSS bundles and\n"
                   "      probes sensitive paths such as /.env and /.git/config.\n"
                   "      --crawl N   also follow N same-host pages.\n"
                   "      --verify    live-check every credential found."),
        "options": ("--crawl --no-recon --max-assets --timeout --user-agent\n"
                    "      --header 'K: V' --only --min-severity --min-entropy\n"
                    "      --no-entropy --no-redact --verify --fail-on\n"
                    "      -e/--export -o/--out --name -q"),
    },
    "verify": {
        "usage": "verify NAME",
        "summary": "Live-check the credentials captured in a saved scan.",
        "detail": ("Each credential is sent to its own issuer only -- no third\n"
                   "      party ever sees the value. The verdict is LIVE,\n"
                   "      DEAD, SKIPPED (no live check) or UNKNOWN (inconclusive)."),
        "options": "NAME",
    },
    "export": {
        "usage": "export NAME -f FORMAT",
        "summary": "Export a saved scan as sarif, json, csv or html.",
        "detail": ("SARIF drops straight into GitHub code scanning and most\n"
                   "      CI dashboards. HTML gives a shareable report."),
        "options": "NAME -f/--format sarif|json|csv|html -o/--out",
    },
    "list": {
        "usage": "list",
        "summary": "List every saved scan.",
        "detail": "Scans live in the report directory, newest first.",
        "options": "",
    },
    "show": {
        "usage": "show NAME",
        "summary": "Display one saved scan in full.",
        "detail": "Shows severity, pattern, location and live status.",
        "options": "NAME",
    },
    "clear": {
        "usage": "clear NAME",
        "summary": "Delete one saved scan from disk.",
        "detail": "Only the redacted report is removed; nothing else is touched.",
        "options": "NAME",
    },
    "ignore": {
        "usage": "ignore list | add VALUE | remove VALUE",
        "summary": "Manage the allowlist of findings to hide.",
        "detail": ("VALUE is a 16-character hash, a pattern name, a\n"
                   "      'regex:...' expression or a raw secret (auto-hashed)."),
        "options": "list | add VALUE | remove VALUE",
    },
    "selftest": {
        "usage": "selftest",
        "summary": "Validate the detection engine offline.",
        "detail": ("Runs the positive, negative and live-verification checks.\n"
                   "      No network access, no credentials needed."),
        "options": "",
    },
    "help": {
        "usage": "help [COMMAND]",
        "summary": "Show this screen, or the detail for one command.",
        "detail": "Every command, flag and exit code on one page.",
        "options": "[COMMAND]",
    },
    "interactive": {
        "usage": "interactive",
        "summary": "Guided menu for people who do not want to memorise flags.",
        "detail": "Prompts for the target and the options you want.",
        "options": "",
    },
}

HELP_GROUPS: List[Tuple[str, List[Tuple[str, str]]]] = [
    ("SCAN", [
        ("scan TARGET", "scan a file / folder / archive / git repo"),
        ("scan TARGET --history", "also scan the full git history"),
        ("scan -", "read the target from stdin"),
        ("url URL", "scan one website: page, JS/CSS assets, recon"),
        ("url URL --crawl 5", "also follow 5 same-host pages"),
        ("url URL --no-recon", "skip the sensitive-path probes"),
        ("urls LIST", "scan every URL in a file, concurrently"),
        ("scan LIST.txt", "a .txt of URLs is scanned target by target"),
    ]),
    ("VERIFY", [
        ("verify NAME", "live-check the credentials in a saved scan"),
        ("scan TARGET --verify", "live-check while scanning"),
        ("url URL --verify", "live-check a website scan"),
    ]),
    ("REPORTS", [
        ("list", "every saved scan"),
        ("show NAME", "show one saved scan"),
        ("export NAME -f sarif", "export sarif / json / csv / html"),
        ("clear NAME", "delete a saved scan"),
    ]),
    ("CONFIG", [
        ("ignore list", "show the allowlist"),
        ("ignore add VALUE", "allowlist a hash / pattern / regex"),
        ("ignore remove VALUE", "remove from the allowlist"),
    ]),
    ("DIAGNOSTICS", [
        ("selftest", "validate the detection engine (offline)"),
        ("help [COMMAND]", "this screen"),
        ("interactive", "guided menu"),
    ]),
]


def ascii_banner() -> None:
    """Print the block-letter banner shown by `help` and a bare invocation."""
    print()
    for word, colour in (("SECRET", R), ("SNIPER", C)):
        rows = ["", "", "", "", ""]
        for char in word:
            glyph = ASCII_FONT.get(char)
            if not glyph:
                continue
            for index, line in enumerate(glyph):
                rows[index] += line + " "
        for row in rows:
            print(f"  {colour}{row.rstrip()}{X}")
    print(f"  {GR}{'─' * 47}{X}")
    print(f"  {B}{W}Leaked credential detection & live verification{X}")
    print(f"  {GR}v{TOOL_VERSION} · by {AUTHOR_NAME} ({AUTHOR_ALIAS}) · "
          f"{AUTHOR_HANDLE}{X}")
    print()


def print_help(topic: Optional[str] = None) -> None:
    """Print the full command reference, or the detail for a single command."""
    if topic:
        key = topic.strip().lower()
        entry = HELP_TOPICS.get(key)
        if entry:
            print(f"\n  {B}{W}{entry['usage']}{X}")
            print(f"  {GR}{'─' * 62}{X}")
            print(f"  {entry['summary']}\n")
            print(f"  {entry['detail']}\n")
            if entry.get("options"):
                print(f"  {W}Options{X}")
                print(f"    {C}{entry['options']}{X}\n")
            return
        print(f"  {R}No such command: {topic}{X}")
        print(f"  {GR}Try one of: {', '.join(sorted(HELP_TOPICS))}{X}\n")

    print(f"\n  {B}{W}WHAT IT HUNTS{X}")
    print(f"    {GR}api keys · access tokens · JWTs · private keys · database URLs{X}")
    print(f"    {GR}AWS · Stripe · OpenAI · Anthropic · GitHub · Slack · Discord ·{X}")
    print(f"    {GR}SendGrid · npm · Telegram · Supabase · Google · Cloudflare · …{X}\n")

    print(f"  {B}{W}COMMANDS{X}")
    for title, entries in HELP_GROUPS:
        print(f"    {W}{title}{X}")
        for usage, summary in entries:
            print(f"      {C}{usage:<26}{X} {GR}{summary}{X}")
        print()

    print(f"  {B}{W}EXAMPLES{X}")
    print(f"    {C}secret_sniper.py url https://target.tld --crawl 3 --verify{X}")
    print(f"    {C}secret_sniper.py urls targets.txt -t 32 --fail-on CRITICAL{X}")
    print(f"    {C}secret_sniper.py scan ./repo --history --fail-on CRITICAL{X}")
    print(f"    {C}secret_sniper.py scan . -e sarif -o out.sarif{X}")
    print(f"    {C}secret_sniper.py export mysite -f html -o report.html{X}\n")

    print(f"  {B}{W}LIVE VERIFICATION{X}")
    print(f"    {R}{B}LIVE{X}    the provider accepted the credential")
    print(f"    {GR}DEAD{X}    the provider rejected it")
    print(f"    {GR}SKIPPED{X} no live check exists for that provider")
    print(f"    {Y}UNKNOWN{X} the check could not complete\n")

    print(f"  {B}{W}EXIT CODES{X}")
    print(f"    {GR}0 clean · 1 a finding reached --fail-on · 2 usage error{X}\n")

    print(f"  {B}{W}REPORTS{X}")
    print(f"    {GR}saved in {DATA_DIR}{X}")
    print(f"    {GR}raw secret values are never written to disk{X}")


def cmd_help(args: argparse.Namespace) -> None:
    """Entry point for `secret_sniper.py help [COMMAND]`."""
    ascii_banner()
    print_help(getattr(args, "topic", None))
    footer()


def footer() -> None:
    print()
    print(f"{GR}{'-' * 64}{X}")
    print(f"{GR}  by {AUTHOR_NAME} ({AUTHOR_HANDLE}) · {AUTHOR_ALIAS}{X}")
    print(f"{GR}  {TELEGRAM_LINK}{X}")
    print(f"{GR}  {REPO_LINK}{X}")
    print(f"{GR}{'-' * 64}{X}")


def render_report(report: Dict, show_all: bool = True, limit: int = 200) -> None:
    print()
    print(f"{R}{'=' * 64}{X}")
    print(f"  {B}{W}SECRET SCAN{X}  ·  {report.get('target', '')}")
    print(f"{R}{'=' * 64}{X}")
    print(f"  {W}Kind        :{X} {report.get('kind', '')}")
    print(f"  {W}Files       :{X} {report.get('files_scanned', 0)}")
    if report.get("commits_scanned"):
        print(f"  {W}Commits     :{X} {report['commits_scanned']}")
    print(f"  {W}Findings    :{X} {G}{len(report.get('findings', []))}{X}")
    print(f"  {W}Risk score  :{X} {Y}{report.get('summary', {}).get('risk_score', 0)}{X}")
    print(f"  {W}Duration    :{X} {report.get('duration_ms', 0)}ms")
    print(f"{R}{'=' * 64}{X}")

    recon = report.get("recon") or []
    exposed = [row for row in recon if row.get("exposed")]
    if recon:
        print(f"\n  {W}RECON{X}  {GR}· {len(recon)} paths probed · "
              f"{len(exposed)} exposed{X}")
        for row in recon:
            if row.get("exposed"):
                mark = f"{R}{B}EXPOSED{X}"
            elif row.get("status") == 200:
                mark = f"{GR}200{X}"
            else:
                mark = f"{GR}{row.get('status', 0)}{X}"
            extra = (f" {R}· {row['secrets']} secrets{X}"
                     if row.get("secrets") else "")
            print(f"    {mark} {row.get('path', '')}{extra}")

    findings = report.get("findings", [])
    if not findings:
        print(f"\n{G}v No secrets detected.{X}")
        if exposed:
            print(f"{GR}  {len(exposed)} sensitive path(s) are still readable "
                  f"- see the RECON block above.{X}")
        print(f"{R}{'=' * 64}{X}")
        return

    by_sev: Dict[str, List[Dict]] = defaultdict(list)
    for finding in findings:
        by_sev[finding["severity"]].append(finding)

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        items = by_sev.get(severity, [])
        if not items:
            continue
        colour = SEV_COLOR.get(severity, W)
        print()
        print(f"{colour}> {severity} ({len(items)}){X}")
        print(f"{GR}{'-' * 64}{X}")
        shown = items if show_all else items[:limit]
        for finding in shown:
            print(f"  {colour}*{X} {B}{finding['pattern']}{X}  "
                  f"{GR}{finding['file']}:{finding['line']}{X}")
            extra = f"  ({finding['confidence']})"
            if finding.get("validation"):
                extra += f" {GR}[{finding['validation']}]{X}"
            if finding.get("live_status"):
                status = finding["live_status"]
                status_colour = {"LIVE": R + B, "DEAD": GR,
                                 "UNKNOWN": Y, "SKIPPED": GR}.get(status, Y)
                extra += f" {status_colour}[{status}]{X}"
            print(f"    {GR}{finding['match']}{X}{extra}")
            if finding.get("commit"):
                print(f"    {GR}-> commit {finding['commit']} · "
                      f"{finding.get('author', '')[:30]}{X}")
        if not show_all and len(items) > len(shown):
            print(f"  {GR}... and {len(items) - len(shown)} more{X}")

    print(f"{R}{'=' * 64}{X}")
    print(f"{Y}! Detection only. No exploitation.{X}")
    print(f"{Y}! Scan only files and repos YOU own or are authorised to audit.{X}")
    print()


def render_list() -> None:
    names: List[str] = []
    if os.path.isdir(DATA_DIR):
        for entry in sorted(os.listdir(DATA_DIR)):
            if entry.endswith(".json") and not entry.endswith(".tmp"):
                names.append(entry[:-5])

    print()
    print(f"{R}{'=' * 64}{X}")
    print(f"  {B}{W}SAVED SCANS{X}")
    print(f"{R}{'=' * 64}{X}")
    if not names:
        print(f"  {GR}(nothing saved yet){X}")
    else:
        for name in names:
            report = load_report(name)
            if not report:
                print(f"  {Y}*{X} {name}  {GR}(unreadable){X}")
                continue
            total = len(report.get("findings", []))
            target = report.get("target", "")[:34]
            when = report.get("started", "")[:19].replace("T", " ")
            print(f"  {G}*{X} {B}{name}{X}  "
                  f"{GR}· {total} findings · {target} · {when}{X}")
    print()


# ═══════════════════════════════════════════════════════════════════════
# COMMANDS
# ═══════════════════════════════════════════════════════════════════════
def _run_scan(target: str, history: bool = False, threads: int = 8,
              max_size_mb: int = 5, only: Optional[str] = None,
              min_severity: str = "LOW", no_entropy: bool = False,
              no_redact: bool = False, allowlist: Optional[Set[str]] = None,
              max_commits: int = 0, since: Optional[str] = None,
              until: Optional[str] = None, name: Optional[str] = None,
              verbose: bool = True, decode_encoded: bool = True,
              follow_archives: bool = True,
              baseline: Optional[str] = None,
              min_entropy: float = 4.2,
              url_list: str = "auto", url_timeout: int = 15,
              url_crawl: int = 0, url_max_assets: int = 25,
              url_recon: bool = False, max_urls: int = 0) -> Optional[Dict]:
    started = now_iso()
    begin = time.time()

    only_cats = {x.strip().lower() for x in only.split(",") if x.strip()} if only else None
    scanner = SecretScanner(
        redact_mode=not no_redact,
        entropy=not no_entropy,
        allowlist=allowlist or set(),
        only_cats=only_cats,
        min_severity=min_severity,
        decode_encoded=decode_encoded,
        min_entropy=min_entropy,
    )

    if target == "-":
        kind = "stdin"
    elif os.path.isdir(target):
        kind = "git" if (history and os.path.isdir(os.path.join(target, ".git"))) else "directory"
    elif os.path.isfile(target):
        kind = "file"
    else:
        print(f"{R}Not found: {target}{X}")
        return None

    if verbose:
        print(f"\n{C}>> Target {B}{target}{X}  {GR}({kind}){X}\n")

    files_scanned = 0
    commits_scanned = 0
    all_findings: List[Dict] = []
    raw_values: Dict[Tuple[str, str], str] = {}
    bulk_stats: Dict[str, Any] = {}
    report_kind = kind

    if kind == "stdin":
        if verbose:
            print(f"{Y}Paste content, then Ctrl+D (or Ctrl+Z on Windows) + Enter:{X}\n")
        try:
            text = sys.stdin.read()
        except KeyboardInterrupt:
            return None
        all_findings = scanner.scan_text(text, source="<stdin>")
        files_scanned = 1

    elif kind == "file":
        ext = os.path.splitext(target)[1].lower()
        is_archive = follow_archives and ext in ARCHIVE_EXTS
        if is_archive:
            all_findings = scanner.scan_archive(target)
        else:
            all_findings = scanner.scan_file(target,
                                              max_bytes=max_size_mb * 1024 * 1024)
        files_scanned = 1
        if verbose:
            print(f"  {G}v{X} scanned · {len(all_findings)} hits")

        # A .txt holding thousands of URLs is a list of *targets*, not a file
        # to grep. Scan the list itself and then every target it points at,
        # so a 9000-URL list reports what those sites really expose.
        if url_list != "off" and not is_archive:
            list_text = _read_text_file(target, max_size_mb * 1024 * 1024)
            detected = bool(list_text) and looks_like_url_list(list_text)
            if list_text and (detected or url_list == "on"):
                urls = extract_urls(list_text)
                if max_urls and len(urls) > max_urls:
                    urls = urls[:max_urls]
                if urls:
                    if verbose:
                        print(f"\n{C}>>{X} URL list · {len(urls)} target(s)"
                              f" {GR}· scanning every target{X}\n")
                    bulk = scan_url_list(urls, scanner, threads=threads,
                                         timeout=url_timeout, crawl=url_crawl,
                                         max_assets=url_max_assets,
                                         recon=url_recon, verbose=verbose)
                    all_findings.extend(bulk["findings"])
                    files_scanned += bulk["targets_unique"]
                    bulk_stats = bulk
                    report_kind = "url-list"

    else:
        files = walk_files(target, follow_archives=follow_archives)
        if verbose:
            print(f"  {G}->{X} {len(files)} candidate files\n")
        all_findings = scan_files_parallel(files, scanner, threads=threads,
                                            verbose=verbose, root=target,
                                            follow_archives=follow_archives)
        files_scanned = len(files)

        if history:
            if os.path.isdir(os.path.join(target, ".git")):
                if verbose:
                    print(f"\n{C}>> Git history{X}")
                hist_findings, commits_scanned = scan_git_history(
                    target, scanner, max_commits=max_commits,
                    since=since, until=until, verbose=verbose)
                seen = {(f["file"], f["pattern"], f["hash"]) for f in all_findings}
                for hit in hist_findings:
                    key = (hit["file"], hit["pattern"], hit["hash"])
                    if key not in seen:
                        seen.add(key)
                        all_findings.append(hit)
            else:
                print(f"  {Y}!{X} {target} is not a git repo · skipping history")

    # ── baseline diff: keep only findings that are new ────────────────
    if baseline:
        base_report = load_report(baseline)
        if base_report is None:
            print(f"{R}Baseline not found: {baseline}{X}")
        else:
            known = {(f["pattern"], f["hash"]) for f in base_report.get("findings", [])}
            before = len(all_findings)
            all_findings = [f for f in all_findings
                            if (f["pattern"], f["hash"]) not in known]
            if verbose:
                print(f"  {C}>>{X} baseline {B}{baseline}{X}: "
                      f"{before - len(all_findings)} known, {len(all_findings)} new")

    all_findings.sort(key=lambda f: (-f.get("risk", 0), f["file"], f["line"]))

    report_name = name or f"scan_{stamp()}"
    duration = int((time.time() - begin) * 1000)

    report = {
        "name": report_name,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "author": AUTHOR_NAME,
        "target": target,
        "kind": report_kind,
        "started": started,
        "finished": now_iso(),
        "duration_ms": duration,
        "history": history,
        "files_scanned": files_scanned,
        "commits_scanned": commits_scanned,
        "options": {
            "only": only,
            "min_severity": min_severity,
            "no_entropy": no_entropy,
            "no_redact": no_redact,
            "threads": threads,
            "decode_encoded": decode_encoded,
            "follow_archives": follow_archives,
            "min_entropy": min_entropy,
            "url_list": url_list,
            "timeout": url_timeout,
            "crawl": url_crawl,
            "max_assets": url_max_assets,
            "recon": url_recon,
            "max_urls": max_urls,
        },
        "findings": all_findings,
        "summary": _build_summary(all_findings),
    }

    if bulk_stats:
        report["targets_total"] = bulk_stats["targets_total"]
        report["targets_unique"] = bulk_stats["targets_unique"]
        report["targets_ok"] = bulk_stats["targets_ok"]
        report["targets_failed"] = bulk_stats["targets_failed"]
        report["sources"] = bulk_stats["sources"]

    path = _save_report(report)
    if verbose:
        print(f"\n{G}v{X} Saved -> {B}{path}{X}")

    return report


def cmd_scan(args: argparse.Namespace) -> Optional[Dict]:
    allowlist = load_allowlist()
    report = _run_scan(
        target=args.target,
        history=args.history,
        threads=args.threads,
        max_size_mb=args.max_size_mb,
        only=args.only,
        min_severity=args.min_severity,
        no_entropy=args.no_entropy,
        no_redact=args.no_redact,
        allowlist=allowlist,
        max_commits=args.max_commits,
        since=args.since,
        until=args.until,
        name=args.name,
        verbose=not args.quiet,
        decode_encoded=not args.no_decode,
        follow_archives=not args.no_archives,
        baseline=args.baseline,
        min_entropy=args.min_entropy,
        url_list=("off" if args.no_url_list else
                  "on" if args.url_list else "auto"),
        url_timeout=args.timeout,
        url_crawl=args.crawl,
        url_max_assets=args.max_assets,
        url_recon=args.recon,
        max_urls=args.max_urls,
    )
    if not report:
        footer()
        return None

    if args.verify:
        print(f"\n{C}>> Live verification (contacting each credential's provider){X}")
        report["findings"] = verify_findings(report["findings"],
                                             verbose=not args.quiet)
        report["summary"] = _build_summary(report["findings"])
        _save_report(report)

    render_report(report, show_all=not args.quiet)

    if args.export:
        do_export(report, args.export, args.out)

    footer()

    if args.fail_on:
        threshold = SEV_ORDER.get(args.fail_on.upper(), 3)
        if any(SEV_ORDER.get(f["severity"], 99) <= threshold
               for f in report["findings"]):
            sys.exit(1)
    return report


def cmd_export(args: argparse.Namespace) -> None:
    report = load_report(args.name)
    if report is None:
        print(f"{R}Scan not found: {args.name}{X}")
        return
    do_export(report, args.format, args.out)
    footer()


def cmd_list(args: argparse.Namespace) -> None:
    render_list()
    footer()


def cmd_show(args: argparse.Namespace) -> None:
    report = load_report(args.name)
    if report is None:
        print(f"{R}Scan not found: {args.name}{X}")
        return
    render_report(report, show_all=True)
    footer()


def cmd_clear(args: argparse.Namespace) -> None:
    path = os.path.join(DATA_DIR, f"{args.name}.json")
    if os.path.exists(path):
        os.remove(path)
        print(f"{G}v{X} Cleared {args.name}")
    else:
        print(f"{Y}Nothing to clear for {args.name}{X}")


def cmd_ignore(args: argparse.Namespace) -> None:
    action = args.action or "list"
    entries = load_allowlist()

    if action == "list":
        print()
        print(f"{R}{'=' * 64}{X}")
        print(f"  {B}{W}ALLOWLIST{X}")
        print(f"{R}{'=' * 64}{X}")
        if not entries:
            print(f"  {GR}(empty){X}")
        else:
            for entry in sorted(entries):
                print(f"  {G}*{X} {entry}")
        print(f"{R}{'=' * 64}{X}")
        print(f"  {GR}global: {ALLOWLIST_FILE}{X}")
        print(f"  {GR}local : {LOCAL_ALLOWLIST} (if present){X}")
        print()

    elif action == "add":
        value = args.value
        if not value:
            print(f"{R}No value provided{X}")
            return
        if re.fullmatch(r"[a-f0-9]{16}", value):
            entries.add(value)
        elif value.startswith("regex:"):
            entries.add(value)
        elif value in {p["name"] for p in PATTERNS}:
            entries.add(value)
        else:
            entries.add(hash_secret(value))
            print(f"{GR}hashed -> {hash_secret(value)}{X}")
        save_allowlist(entries)
        print(f"{G}v{X} Added to allowlist")

    elif action == "remove":
        value = args.value
        if not value:
            print(f"{R}No value provided{X}")
            return
        found = False
        for entry in list(entries):
            if entry == value or entry == hash_secret(value):
                entries.discard(entry)
                found = True
        save_allowlist(entries)
        print(f"{G}v{X} Removed" if found else f"{Y}Not in allowlist{X}")

    footer()


def cmd_verify(args: argparse.Namespace) -> None:
    """Re-scan a saved target and live-check the credentials it contains.

    Raw secret values are never written to disk, so verification re-reads
    the original target instead of trusting the stored (redacted) report.
    """
    report = load_report(args.name)
    if report is None:
        print(f"{R}Scan not found: {args.name}{X}")
        return

    target = report.get("target", "")
    options = report.get("options", {})
    if not target or target == "<stdin>":
        print(f"{Y}! Target '{target}' cannot be re-read; "
              f"run 'scan <target> --verify' instead.{X}")
        footer()
        return

    print(f"\n{C}>> Re-scanning {target} for live verification{X}\n")
    fresh = _run_scan(
        target=target,
        history=report.get("history", False),
        threads=options.get("threads", 8),
        max_size_mb=options.get("max_size_mb", 5),
        only=options.get("only"),
        min_severity=options.get("min_severity", "LOW"),
        no_entropy=options.get("no_entropy", False),
        no_redact=False,
        allowlist=load_allowlist(),
        max_commits=0,
        name=report.get("name"),
        verbose=True,
        decode_encoded=options.get("decode_encoded", True),
        follow_archives=options.get("follow_archives", True),
        min_entropy=options.get("min_entropy", 4.2),
        url_list=options.get("url_list", "auto"),
        url_timeout=options.get("timeout", 15),
        url_crawl=options.get("crawl", 0),
        url_max_assets=options.get("max_assets", 25),
        url_recon=options.get("recon", False),
        max_urls=options.get("max_urls", 0),
    )
    if not fresh:
        footer()
        return

    print(f"\n{C}>> Verifying {len(fresh.get('findings', []))} findings{X}")
    fresh["findings"] = verify_findings(fresh.get("findings", []))
    fresh["summary"] = _build_summary(fresh["findings"])
    _save_report(fresh)
    render_report(fresh, show_all=False)
    footer()


# ═══════════════════════════════════════════════════════════════════════
# SELF TEST
# ═══════════════════════════════════════════════════════════════════════
def _frag(*parts: str) -> str:
    """Assemble a synthetic test vector from fragments at runtime.

    Every value in this table is an obviously fake placeholder, but GitHub's
    push protection rejects a file that contains several *fully formed*
    credential literals at once -- fake ones included. Joining the fragments
    here keeps each assembled value byte-identical (so detection behaviour is
    unchanged) while guaranteeing that no complete credential string ever
    appears verbatim in the committed source.
    """
    return "".join(parts)


SELFTEST_POSITIVES: List[Tuple[str, str]] = [
    ("github", "token = \"ghp_" + "a1B2c3D4e5F6" + "g7H8i9J0k1L2"
     + "m3N4o5P6q7R8" + "\""),
    ("stripe", "STRIPE_KEY=" + "sk_live_51H8" + "xYzabcdefghij" + "klmnop"),
    ("aws", "aws_access_key_id = " + "AKIAIOSF" + "ODNN7EXAMPLE"),
    ("openai", "OPENAI_API_KEY=\"sk-proj-" + "Ab3Cd4Ef5Gh6Ij7"
     + "Kl8Mn9Op0Qr1St2U" + "v3Wx4Yz5" + "\""),
    ("slack", "SLACK_TOKEN=" + "xoxb-123456" + "789012-123456789"
     + "0123-abcdefghij" + "klmnopqrstuvwx"),
    ("telegram", "TELEGRAM_TOKEN=" + "1234567890:AAH" + "kVvJ0lmnOpQrst"
     + "UvwXyz1234567890" + "ab"),
    ("jwt", "auth = " + "eyJhbGciOiJIUzI1" + "NiIsInR5cCI6IkpX"
     + "VCJ9.eyJzdWIiOi" + "IxMjM0" + "NTY3ODkwIiwib" + "mFtZS"
     + "I6IkpvaG4ifQ." + "SflKxwR" + "JSMeKKF2QT4fw" + "pMeJf"
     + "36POk6yJV_ad" + "Qssw5c"),
    ("private-key", "-----BEGIN RSA PRIVATE KEY-----" + "\nMIIEowIBAAK"
     + "CAQEA" + "\n-----END RSA PRIVATE KEY-----"),
    ("database", "DATABASE_URL=" + "postgres://" + "admin:" + "s3cr3tpass@db."
     + "internal:5432" + "/app"),
    ("sendgrid", "SENDGRID=" + "SG.abc123XYZ" + "_def456GHI.789" + "jkl"
     + "012MNO345pqr678" + "STU"),
    ("npm", "NPM_TOKEN=" + "npm_" + "aBcDeFgHiJkLmNoP" + "qRsTuVwXyZ012345"
     + "6789"),
    ("supabase", "SUPABASE=" + "sbp_" + "a" * 40),
    ("anthropic", "ANTHROPIC=" + "sk-ant-api03-" + "AbCdEfGhIjKlMnOp"
     + "QrStUvWxYz012345" + "6789"),
    ("google", "GOOGLE_KEY=" + "AIzaSyB7c" + "D2eF4gH6iJ8kL0m"
     + "N2pQ4rS6tU8vW0x"),
    ("discord", "DISCORD_TOKEN=" + "MTIzNDU2" + "Nzg5MDEyMzQ1Njc4"
     + ".GaBcDe.fFgHiJk" + "LmNoPqRsTuVwXyZ" + "01234"),
    ("generic", "password = \"" + "Xq7bZ2mK9pL" + "4wR8tY1nC6dF3gH5"
     + "jS0vA\""),
    ("huggingface", "HF_TOKEN=" + "hf_AbCdEfGh" + "IjKlMnOpQrStUvWx"
     + "Yz01234567"),
]

SELFTEST_NEGATIVES: List[Tuple[str, str]] = [
    ("placeholder", 'password = "changeme"'),
    ("placeholder", 'api_key = "your_api_key_here"'),
    ("doc", "# Install with: pip install requests"),
    ("doc", "See https://example.com/docs for details"),
    ("hash", "sha256 = " + "a" * 64),
    ("uuid", "id = 123e4567-e89b-12d3-a456-426614174000"),
    ("normal", "def scan_file(path):\n    return os.path.getsize(path)"),
    ("normal", 'print("Hello, world!")'),
]


# ── offline live-verification regression tests ──────────────────────
# Several issuer APIs answer HTTP 200 even when the credential is invalid and
# put the real verdict in the JSON body -- Slack's ``auth.test`` returns
# ``{"ok": false, "error": "invalid_auth"}``. Judging a 200 by its status
# code alone reported dead Slack tokens as LIVE. These checks pin the
# body-aware verdict down without touching the network.
class _FakeHTTPResponse:
    """Minimal stand-in for a `requests` response object."""

    def __init__(self, status_code: int, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("response has no JSON body")
        return self._payload


class _FakeRequests:
    """Stand-in for the `requests` module captured by `verify_secret`."""

    def __init__(self, response: Any) -> None:
        self._response = response
        self.calls: List[Tuple[str, str]] = []

    def request(self, method: str, url: str, headers: Any = None,
                timeout: Any = None) -> Any:
        self.calls.append((method, url))
        return self._response


class _fake_transport:
    """Context manager that swaps a fake `requests` module into sys.modules."""

    def __init__(self, response: Any) -> None:
        self._module = _FakeRequests(response)
        self._saved: Any = None

    def __enter__(self) -> _FakeRequests:
        self._saved = sys.modules.get("requests")
        sys.modules["requests"] = self._module
        return self._module

    def __exit__(self, *exc: Any) -> None:
        if self._saved is None:
            sys.modules.pop("requests", None)
        else:
            sys.modules["requests"] = self._saved


def _verdict_with(pattern: str, status_code: int, payload: Any = None) -> str:
    """Run `verify_secret` against a fake provider response, fully offline."""
    with _fake_transport(_FakeHTTPResponse(status_code, payload)):
        status, _detail = verify_secret(pattern, "test-token-value", timeout=5)
    return status


SELFTEST_BODY_CHECKS: List[Tuple[str, Callable[[], Any]]] = [
    ("slack-invalid", lambda: _body_rejects_credential(
        {"ok": False, "error": "invalid_auth"}) is True),
    ("slack-valid", lambda: _body_rejects_credential(
        {"ok": True, "user": "U012345"}) is False),
    ("cloudflare-invalid", lambda: _body_rejects_credential(
        {"success": False, "errors": [{"code": 1000}]}) is True),
    ("cloudflare-active", lambda: _body_rejects_credential(
        {"success": True, "result": {"id": "token"}}) is False),
    ("nested-invalid", lambda: _body_rejects_credential(
        {"result": {"status": "invalid"}}) is True),
    ("not-a-dict", lambda: _body_rejects_credential("plain text body") is False),
]

SELFTEST_VERDICT_CHECKS: List[Tuple[str, Callable[[], Any]]] = [
    ("slack-200-invalid-body", lambda: _verdict_with(
        "Slack Bot Token", 200, {"ok": False, "error": "invalid_auth"}) == "DEAD"),
    ("slack-200-valid-body", lambda: _verdict_with(
        "Slack Bot Token", 200, {"ok": True, "user": "U012345"}) == "LIVE"),
    ("slack-401-body", lambda: _verdict_with(
        "Slack Bot Token", 401, {"ok": False, "error": "invalid_auth"}) == "DEAD"),
    ("no-verifier-skipped", lambda: _verdict_with(
        "Pattern Without Verifier", 200, {"ok": True}) == "SKIPPED"),
]


def _generic_hits(sample: str, pattern: str) -> int:
    """Count hits of one generic rule on a single sample line."""
    scanner = SecretScanner(redact_mode=True, entropy=False, min_severity="LOW")
    return sum(1 for hit in scanner.scan_text(sample, source="<selftest>")
               if hit["pattern"] == pattern)


SELFTEST_IDENTIFIER_CHECKS: List[Tuple[str, Callable[[], Any]]] = [
    ("openapi-type-name", lambda: looks_like_identifier(
        "OpenapiGetV1AccountSecurityAnomalyApiKeysInput") is True),
    ("snake-case-field", lambda: looks_like_identifier(
        "specified_by_request") is True),
    ("camel-case-field", lambda: looks_like_identifier(
        "linkClientSecret") is True),
    ("upper-snake-constant", lambda: looks_like_identifier(
        "V2_ORGANIZATION_APIKEYS_SECRET") is True),
    ("random-mixed-case", lambda: looks_like_identifier(
        "Xq7bZ2mK9pL" + "4wR8tY1nC6dF3gH5" + "jS0vA") is False),
    ("random-hex", lambda: looks_like_identifier(
        "a3f9b2c8d1e4" + "f7a0b5c9d2e6f3" + "a8b1c") is False),
    ("prefixed-key", lambda: looks_like_identifier(
        "sk_live_51H8" + "xYzabcdefghij" + "klmnop") is False),
    ("code-fragment", lambda: looks_like_code_fragment(
        ",l.username=") is True),
    ("base64-value-not-code", lambda: looks_like_code_fragment(
        "Xy7bZ2mK9pL" + "4wR8tY1nC6dF3gH5" + "jS0vA+/x=") is False),
    ("bundle-noise-not-reported", lambda: _generic_hits(
        'apiKey:"specified_by_request"', "Generic API Key") == 0),
    ("real-looking-value-reported", lambda: _generic_hits(
        'apiKey:"' + "Xq7bZ2mK9pL" + "4wR8tY1nC6dF3gH5" + "jS0vA" + '"',
        "Generic API Key") == 1),
    ("bundle-password-noise-not-reported", lambda: _generic_hits(
        'password=",l.username="', "Generic Password") == 0),
]

# A second family of "not a secret" shapes was found by scanning real sites:
# dotted translation keys, short method names and provider object ids.
SELFTEST_SHAPE_CHECKS: List[Tuple[str, Callable[[], Any]]] = [
    ("dotted-camel-path", lambda: looks_like_identifier(
        "docsShell.glossary.term.genericClientSecret") is True),
    ("dotted-snake-path", lambda: looks_like_identifier(
        "link.auth_session_client_secret") is True),
    ("short-camel-method", lambda: looks_like_identifier("getHost") is True),
    ("short-camel-method-2", lambda: looks_like_identifier("setHost") is True),
    ("short-value-with-digits-kept", lambda: looks_like_identifier(
        "Xq7bZ2") is False),
    ("dotted-random-kept", lambda: looks_like_identifier(
        "a1b2c3d4" + "." + "e5f6g7h8") is False),
    ("public-object-id", lambda: looks_like_public_object_id(
        "ch_3LiiC52eZ" + "vKYlo2C1da66ZSQ") is True),
    ("public-object-id-short", lambda: looks_like_public_object_id(
        "ch_3abc") is False),
    ("secret-key-not-object-id", lambda: looks_like_public_object_id(
        "sk_live_51H8" + "xYzabcdefghij" + "klmnop") is False),
    ("dotted-path-not-reported", lambda: _generic_hits(
        '{"id":"docsShell.glossary.term.secretKey"}', "Generic Secret") == 0),
    ("short-method-not-reported", lambda: _generic_hits(
        'password:"getHost"', "Generic Password") == 0),
    ("object-id-not-reported", lambda: _generic_hits(
        'api_key: "ch_3LiiC52eZ' + 'vKYlo2C1da66ZSQ"',
        "Generic API Key") == 0),
    ("real-secret-still-reported", lambda: _generic_hits(
        'client_secret:"' + "Xq7bZ2mK9pL" + "4wR8tY1nC6dF3gH5" + "jS0vA" + '"',
        "Generic Secret") == 1),
    ("real-password-still-reported", lambda: _generic_hits(
        'password:"Xq7bZ2"', "Generic Password") == 1),
]


# ── bulk URL-list scanning ───────────────────────────────────────────
# A .txt file holding thousands of URLs must be treated as a list of
# *targets* to visit, not as a file whose text happens to contain secrets.
# These checks pin down the list parser and the scanner's behaviour when
# many workers share a single instance.
def _depth_is_thread_local() -> bool:
    """The recursion guard must be per-thread, not per-scanner.

    A shared guard lets one worker's encoded-payload scan suppress every
    other worker's encoded-secret detection, which silently under-reports.
    """
    scanner = SecretScanner(redact_mode=True)
    seen: Dict[str, Any] = {}

    def worker() -> None:
        scanner._depth = 7
        seen["value"] = scanner._depth

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=10)
    return seen.get("value") == 7 and scanner._depth == 0


def _concurrent_encoded_scan() -> bool:
    """Two workers sharing one scanner must both detect an encoded secret."""
    secret = "sk_" + "live_" + "51H8xYz" + "abcdefghij" + "klmnop"
    blob = base64.b64encode(secret.encode()).decode("ascii")
    scanner = SecretScanner(redact_mode=True)
    barrier = threading.Barrier(2)
    counts: List[int] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait(timeout=10)
        hits = [f for f in scanner.scan_text('data = "' + blob + '"',
                                             source="<selftest>")
                if f["pattern"].startswith("Encoded Secret")]
        with lock:
            counts.append(len(hits))

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    return len(counts) == 2 and all(count > 0 for count in counts)


SELFTEST_BULK_CHECKS: List[Tuple[str, Callable[[], Any]]] = [
    ("extract-urls", lambda: extract_urls(
        "http://a.example/x\nhttps://b.example/y\n")
     == ["http://a.example/x", "https://b.example/y"]),
    ("extract-urls-skips-comments", lambda: extract_urls(
        "# a comment\n\nhttp://a.example/x\n") == ["http://a.example/x"]),
    ("extract-urls-skips-non-http", lambda: extract_urls(
        "ftp://a.example/x\nfile:///etc/passwd\nhttp://a.example/y\n")
     == ["http://a.example/y"]),
    ("url-list-detected", lambda: looks_like_url_list(
        "".join("http://host" + str(i) + ".example/page\n" for i in range(8)))
     is True),
    ("secret-file-not-a-url-list", lambda: looks_like_url_list(
        ("STRIPE_KEY=" + "sk_" + "live_" + "abc\n"
         + "GITHUB_TOKEN=" + "ghp_" + "abcdefghij\n") * 8) is False),
    ("few-urls-not-a-url-list", lambda: looks_like_url_list(
        "http://a.example/x\nhttp://b.example/y\n") is False),
    ("depth-is-thread-local", _depth_is_thread_local),
    ("concurrent-encoded-scan", _concurrent_encoded_scan),
]


def cmd_selftest(args: argparse.Namespace) -> int:
    """Validate the detection engine against known positive/negative samples."""
    scanner = SecretScanner(redact_mode=True, entropy=False, min_severity="LOW")
    passed = 0
    failed: List[str] = []

    print()
    print(f"{R}{'=' * 64}{X}")
    print(f"  {B}{W}SELFTEST{X} · {TOOL_NAME} v{TOOL_VERSION}")
    print(f"{R}{'=' * 64}{X}")

    print(f"\n  {W}Positives (must detect):{X}")
    for category, sample in SELFTEST_POSITIVES:
        hits = scanner.scan_text(sample, source="<selftest>")
        matched = any(h["category"] == category for h in hits)
        ok = matched or (category == "generic" and bool(hits))
        if ok:
            passed += 1
            print(f"    {G}PASS{X} [{category:<12}] {sample[:52]}")
        else:
            failed.append(f"positive[{category}]: {sample[:60]}")
            print(f"    {R}FAIL{X} [{category:<12}] {sample[:52]}")

    print(f"\n  {W}Negatives (must not trigger):{X}")
    for label, sample in SELFTEST_NEGATIVES:
        hits = scanner.scan_text(sample, source="<selftest>")
        bad = [h for h in hits if h["severity"] in ("CRITICAL", "HIGH")]
        if not bad:
            passed += 1
            print(f"    {G}PASS{X} [{label:<12}] {sample[:52]}")
        else:
            failed.append(f"negative[{label}]: {sample[:60]}")
            print(f"    {R}FAIL{X} [{label:<12}] "
                  f"-> {', '.join(h['pattern'] for h in bad)}")

    print(f"\n  {W}Live-verification body semantics (must read the body):{X}")
    for label, check in SELFTEST_BODY_CHECKS:
        detail = ""
        try:
            ok = bool(check())
        except Exception as exc:
            ok = False
            detail = f"  [{type(exc).__name__}]"
        if ok:
            passed += 1
            print(f"    {G}PASS{X} [{label:<24}]")
        else:
            failed.append(f"body-check[{label}]{detail}")
            print(f"    {R}FAIL{X} [{label:<24}]{detail}")

    print(f"\n  {W}Live-verification verdicts (must not call dead keys LIVE):{X}")
    for label, check in SELFTEST_VERDICT_CHECKS:
        detail = ""
        try:
            ok = bool(check())
        except Exception as exc:
            ok = False
            detail = f"  [{type(exc).__name__}]"
        if ok:
            passed += 1
            print(f"    {G}PASS{X} [{label:<24}]")
        else:
            failed.append(f"verdict[{label}]{detail}")
            print(f"    {R}FAIL{X} [{label:<24}]{detail}")

    print(f"\n  {W}Identifier-vs-secret discrimination:{X}")
    for label, check in SELFTEST_IDENTIFIER_CHECKS:
        detail = ""
        try:
            ok = bool(check())
        except Exception as exc:
            ok = False
            detail = f"  [{type(exc).__name__}]"
        if ok:
            passed += 1
            print(f"    {G}PASS{X} [{label:<28}]")
        else:
            failed.append(f"identifier[{label}]{detail}")
            print(f"    {R}FAIL{X} [{label:<28}]{detail}")

    print(f"\n  {W}Non-secret shape discrimination:{X}")
    for label, check in SELFTEST_SHAPE_CHECKS:
        detail = ""
        try:
            ok = bool(check())
        except Exception as exc:
            ok = False
            detail = f"  [{type(exc).__name__}]"
        if ok:
            passed += 1
            print(f"    {G}PASS{X} [{label:<28}]")
        else:
            failed.append(f"shape[{label}]{detail}")
            print(f"    {R}FAIL{X} [{label:<28}]{detail}")

    print(f"\n  {W}Bulk URL-list scanning and concurrency:{X}")
    for label, check in SELFTEST_BULK_CHECKS:
        detail = ""
        try:
            ok = bool(check())
        except Exception as exc:
            ok = False
            detail = f"  [{type(exc).__name__}]"
        if ok:
            passed += 1
            print(f"    {G}PASS{X} [{label:<28}]")
        else:
            failed.append(f"bulk[{label}]{detail}")
            print(f"    {R}FAIL{X} [{label:<28}]{detail}")

    total = (len(SELFTEST_POSITIVES) + len(SELFTEST_NEGATIVES)
             + len(SELFTEST_BODY_CHECKS) + len(SELFTEST_VERDICT_CHECKS)
             + len(SELFTEST_IDENTIFIER_CHECKS) + len(SELFTEST_SHAPE_CHECKS)
             + len(SELFTEST_BULK_CHECKS))
    print()
    print(f"{R}{'=' * 64}{X}")
    if failed:
        print(f"  {R}SELFTEST FAILED{X}  {passed}/{total} passed")
        for item in failed:
            print(f"    {R}-{X} {item}")
        print(f"{R}{'=' * 64}{X}")
        footer()
        return 1

    print(f"  {G}SELFTEST PASSED{X}  {passed}/{total} checks")
    print(f"{R}{'=' * 64}{X}")
    footer()
    return 0


# ═══════════════════════════════════════════════════════════════════════
# INTERACTIVE
# ═══════════════════════════════════════════════════════════════════════
def interactive() -> None:
    while True:
        print(f"\n{W}[1]{X} Scan a file")
        print(f"{W}[2]{X} Scan a directory")
        print(f"{W}[3]{X} Scan a git repo (working tree)")
        print(f"{W}[4]{X} Scan a git repo (full history)")
        print(f"{W}[5]{X} Scan from stdin")
        print(f"{W}[6]{X} Export a saved scan")
        print(f"{W}[7]{X} List saved scans")
        print(f"{W}[8]{X} Show a saved scan")
        print(f"{W}[9]{X} Clear a saved scan")
        print(f"{W}[10]{X} Manage allowlist")
        print(f"{W}[11]{X} Verify credentials in a saved scan")
        print(f"{W}[12]{X} Run self-test")
        print(f"{W}[13]{X} Scan a website (URL)")
        print(f"{W}[14]{X} Show the command reference")
        print(f"{W}[15]{X} Exit")
        choice = input(f"\n{W}> {X}").strip()

        if choice in ("1", "2", "3", "4"):
            target = input(f"{W}Target: {X}").strip()
            if not target:
                continue
            cmd_scan(argparse.Namespace(
                target=target, history=(choice == "4"), threads=20,
                max_size_mb=5, only=None, min_severity="LOW",
                no_entropy=False, no_redact=False, max_commits=0,
                since=None, until=None, name=None, export=None, out=None,
                quiet=False, no_decode=False, no_archives=False,
                baseline=None, verify=False, min_entropy=4.2, fail_on=None,
                url_list=False, no_url_list=False, timeout=15, crawl=0,
                max_assets=25, recon=False, max_urls=0,
            ))
        elif choice == "5":
            cmd_scan(argparse.Namespace(
                target="-", history=False, threads=20, max_size_mb=5,
                only=None, min_severity="LOW", no_entropy=False,
                no_redact=False, max_commits=0, since=None, until=None,
                name=None, export=None, out=None, quiet=False,
                no_decode=False, no_archives=False, baseline=None,
                verify=False, min_entropy=4.2, fail_on=None,
                url_list=False, no_url_list=False, timeout=15, crawl=0,
                max_assets=25, recon=False, max_urls=0,
            ))
        elif choice == "6":
            name = input(f"{W}Scan name: {X}").strip()
            if not name:
                continue
            fmt = input(f"{W}Format [sarif/json/csv/html]: {X}").strip() or "sarif"
            out = input(f"{W}Output file (blank auto): {X}").strip() or None
            cmd_export(argparse.Namespace(name=name, format=fmt, out=out))
        elif choice == "7":
            cmd_list(argparse.Namespace())
        elif choice == "8":
            name = input(f"{W}Scan name: {X}").strip()
            if name:
                cmd_show(argparse.Namespace(name=name))
        elif choice == "9":
            name = input(f"{W}Scan name: {X}").strip()
            if name:
                cmd_clear(argparse.Namespace(name=name))
        elif choice == "10":
            action = input(f"{W}Action [list/add/remove]: {X}").strip() or "list"
            value = None
            if action in ("add", "remove"):
                value = input(f"{W}Value (hash / pattern name / regex:...): {X}").strip()
            cmd_ignore(argparse.Namespace(action=action, value=value))
        elif choice == "11":
            name = input(f"{W}Scan name: {X}").strip()
            if name:
                cmd_verify(argparse.Namespace(name=name))
        elif choice == "12":
            cmd_selftest(argparse.Namespace())
        elif choice == "13":
            target = input(f"{W}Website URL: {X}").strip()
            if not target:
                continue
            cmd_url(argparse.Namespace(
                url=target, crawl=0, no_recon=False, max_assets=25,
                timeout=15, user_agent=None, header=[], only=None,
                min_severity="LOW", no_entropy=False, no_redact=False,
                min_entropy=4.2, name=None, verify=False, fail_on=None,
                export=None, out=None, quiet=False,
            ))
        elif choice == "14":
            cmd_help(argparse.Namespace(topic=None))
        elif choice == "15":
            print(f"\n{GR}Bye.{X}\n")
            return


# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret_sniper",
        description=f"{TOOL_NAME} v{TOOL_VERSION} — leaked credential "
                    f"detection & live verification · by {AUTHOR_NAME} "
                    f"({AUTHOR_HANDLE})",
        epilog=(
            "commands:\n"
            "  scan TARGET          scan a file / folder / archive / git repo\n"
            "  url URL              scan a single website (page, JS assets, recon)\n"
            "  verify NAME          live-check the credentials in a saved scan\n"
            "  export NAME -f F     export sarif / json / csv / html\n"
            "  list | show | clear  manage saved scans\n"
            "  ignore list|add|rm   manage the allowlist\n"
            "  selftest             validate the detection engine (offline)\n"
            "  help [COMMAND]       the full command reference\n"
            "\n"
            "examples:\n"
            "  secret_sniper.py url https://target.tld --crawl 3 --verify\n"
            "  secret_sniper.py scan ./repo --history --fail-on CRITICAL\n"
            "  secret_sniper.py export mysite -f html -o report.html\n"
            "\n"
            f"reports: {DATA_DIR}\n"
            f"Telegram: {TELEGRAM_LINK}  |  GitHub: {GITHUB_LINK}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd")

    scan = sub.add_parser("scan", help="scan a file / directory / archive / git repo / stdin")
    scan.add_argument("target", help="path, git repo, archive, or '-' for stdin")
    scan.add_argument("--history", action="store_true",
                      help="include full git history (repo only)")
    scan.add_argument("-t", "--threads", type=int, default=20,
                      help="worker threads (default 20)")
    scan.add_argument("--max-size-mb", type=int, default=5,
                      help="skip files larger than N MB (default 5)")
    scan.add_argument("--url-list", action="store_true",
                      help="treat the file as a list of URLs and scan every target")
    scan.add_argument("--no-url-list", action="store_true",
                      help="never treat a file as a URL list (plain file scan only)")
    scan.add_argument("--timeout", type=int, default=15,
                      help="per-request timeout for URL-list scans (default 15)")
    scan.add_argument("--crawl", type=int, default=0,
                      help="also follow N same-host pages per URL-list target")
    scan.add_argument("--max-assets", type=int, default=25,
                      help="maximum JS/CSS assets per URL-list target (default 25)")
    scan.add_argument("--recon", action="store_true",
                      help="probe sensitive paths on every URL-list target")
    scan.add_argument("--max-urls", type=int, default=0,
                      help="scan at most N targets from a URL list (0 = all)")
    scan.add_argument("--only", default=None,
                      help="comma-separated categories: aws,github,stripe,openai,"
                           "discord,jwt,private-key,database,generic,entropy,encoded,...")
    scan.add_argument("--min-severity", default="LOW",
                      choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    scan.add_argument("--no-entropy", action="store_true",
                      help="disable entropy-based detection")
    scan.add_argument("--no-redact", action="store_true",
                      help="show raw secret values (careful!)")
    scan.add_argument("--no-decode", action="store_true",
                      help="disable base64/hex encoded-payload scanning")
    scan.add_argument("--no-archives", action="store_true",
                      help="do not expand archives")
    scan.add_argument("--min-entropy", type=float, default=4.2,
                      help="entropy threshold for generic detection (default 4.2)")
    scan.add_argument("--max-commits", type=int, default=0,
                      help="limit git history depth (0 = all)")
    scan.add_argument("--since", default=None, help="git log --since (YYYY-MM-DD)")
    scan.add_argument("--until", default=None, help="git log --until")
    scan.add_argument("--name", default=None, help="save scan under this name")
    scan.add_argument("--baseline", default=None,
                      help="only report secrets that are new vs this saved scan")
    scan.add_argument("--verify", action="store_true",
                      help="live-check detected credentials against their provider")
    scan.add_argument("--fail-on", default=None,
                      choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                      help="exit with code 1 when a finding reaches this severity")
    scan.add_argument("-e", "--export", default=None,
                      choices=["sarif", "json", "csv", "html"],
                      help="also export in this format")
    scan.add_argument("-o", "--out", default=None, help="export output file")
    scan.add_argument("-q", "--quiet", action="store_true")

    url = sub.add_parser("url", help="scan a single website")
    url.add_argument("url", help="http(s) URL of the site to scan")
    url.add_argument("--crawl", type=int, default=0,
                     help="also follow N same-host pages (default 0)")
    url.add_argument("--no-recon", action="store_true",
                     help="skip the sensitive-path probes")
    url.add_argument("--max-assets", type=int, default=25,
                     help="maximum JS/CSS assets to download (default 25)")
    url.add_argument("--timeout", type=int, default=15,
                     help="per-request timeout in seconds (default 15)")
    url.add_argument("--user-agent", default=None,
                     help="override the User-Agent header")
    url.add_argument("--header", action="append", default=[],
                     help="extra request header 'Name: value' (repeatable)")
    url.add_argument("--only", default=None,
                     help="comma-separated categories: aws,github,stripe,openai,"
                          "discord,jwt,private-key,database,generic,entropy,...")
    url.add_argument("--min-severity", default="LOW",
                     choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    url.add_argument("--no-entropy", action="store_true",
                     help="disable entropy-based detection")
    url.add_argument("--no-redact", action="store_true",
                     help="show raw secret values (careful!)")
    url.add_argument("--min-entropy", type=float, default=4.2,
                     help="entropy threshold for generic detection (default 4.2)")
    url.add_argument("--name", default=None, help="save scan under this name")
    url.add_argument("--verify", action="store_true",
                     help="live-check detected credentials against their provider")
    url.add_argument("--fail-on", default=None,
                     choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                     help="exit with code 1 when a finding reaches this severity")
    url.add_argument("-e", "--export", default=None,
                     choices=["sarif", "json", "csv", "html"],
                     help="also export in this format")
    url.add_argument("-o", "--out", default=None, help="export output file")
    url.add_argument("-q", "--quiet", action="store_true")

    urls_cmd = sub.add_parser("urls",
                              help="scan every URL listed in a file")
    urls_cmd.add_argument("list_file",
                          help="file holding one http(s) URL per line")
    urls_cmd.add_argument("-t", "--threads", type=int, default=20,
                          help="worker threads (default 20)")
    urls_cmd.add_argument("--timeout", type=int, default=10,
                          help="per-request timeout in seconds (default 10)")
    urls_cmd.add_argument("--crawl", type=int, default=0,
                          help="also follow N same-host pages per target (default 0)")
    urls_cmd.add_argument("--max-assets", type=int, default=25,
                          help="maximum JS/CSS assets per target (default 25)")
    urls_cmd.add_argument("--recon", action="store_true",
                          help="probe sensitive paths on every target "
                               "(8 extra requests each)")
    urls_cmd.add_argument("--max-urls", type=int, default=0,
                          help="scan at most N targets (0 = all)")
    urls_cmd.add_argument("--only", default=None,
                          help="comma-separated categories: aws,github,stripe,openai,"
                               "discord,jwt,private-key,database,generic,entropy,...")
    urls_cmd.add_argument("--min-severity", default="LOW",
                          choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    urls_cmd.add_argument("--no-entropy", action="store_true",
                          help="disable entropy-based detection")
    urls_cmd.add_argument("--no-redact", action="store_true",
                          help="show raw secret values (careful!)")
    urls_cmd.add_argument("--min-entropy", type=float, default=4.2,
                          help="entropy threshold for generic detection (default 4.2)")
    urls_cmd.add_argument("--name", default=None, help="save scan under this name")
    urls_cmd.add_argument("--verify", action="store_true",
                          help="live-check detected credentials against their provider")
    urls_cmd.add_argument("--fail-on", default=None,
                          choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                          help="exit with code 1 when a finding reaches this severity")
    urls_cmd.add_argument("-e", "--export", default=None,
                          choices=["sarif", "json", "csv", "html"],
                          help="also export in this format")
    urls_cmd.add_argument("-o", "--out", default=None, help="export output file")
    urls_cmd.add_argument("-q", "--quiet", action="store_true")

    export = sub.add_parser("export", help="export a saved scan")
    export.add_argument("name")
    export.add_argument("-f", "--format", default="sarif",
                        choices=["sarif", "json", "csv", "html"])
    export.add_argument("-o", "--out", default=None)

    sub.add_parser("list", help="list saved scans")

    show = sub.add_parser("show", help="display a saved scan")
    show.add_argument("name")

    clear = sub.add_parser("clear", help="delete a saved scan")
    clear.add_argument("name")

    verify = sub.add_parser("verify", help="live-check credentials in a saved scan")
    verify.add_argument("name")

    ignore = sub.add_parser("ignore", help="manage the allowlist")
    ignore_sub = ignore.add_subparsers(dest="action")
    ignore_sub.add_parser("list", help="show allowlist")
    add = ignore_sub.add_parser("add", help="add to allowlist")
    add.add_argument("value",
                     help="16-char hash, pattern name, regex:..., or raw secret (auto-hashed)")
    remove = ignore_sub.add_parser("remove", help="remove from allowlist")
    remove.add_argument("value")

    sub.add_parser("selftest", help="validate the detection engine")

    help_cmd = sub.add_parser("help", help="show the full command reference")
    help_cmd.add_argument("topic", nargs="?", default=None,
                           help="show the detail for one command")

    sub.add_parser("interactive", help="guided interactive menu")

    return parser


def main() -> int:
    _safe_stdout()
    _migrate_legacy_data_dir()

    # A bare invocation prints the full reference instead of dropping the
    # user straight into a menu they did not ask for.
    if len(sys.argv) == 1:
        ascii_banner()
        print_help()
        footer()
        return 0

    parser = build_parser()
    args = parser.parse_args()

    if not args.cmd:
        ascii_banner()
        print_help()
        footer()
        return 0

    if args.cmd == "help":
        cmd_help(args)
        return 0

    banner()

    try:
        if args.cmd == "scan":
            cmd_scan(args)
        elif args.cmd == "url":
            cmd_url(args)
        elif args.cmd == "urls":
            cmd_urls(args)
        elif args.cmd == "export":
            cmd_export(args)
        elif args.cmd == "list":
            cmd_list(args)
        elif args.cmd == "show":
            cmd_show(args)
        elif args.cmd == "clear":
            cmd_clear(args)
        elif args.cmd == "ignore":
            cmd_ignore(args)
        elif args.cmd == "verify":
            cmd_verify(args)
        elif args.cmd == "interactive":
            interactive()
        elif args.cmd == "selftest":
            return cmd_selftest(args)
    except KeyboardInterrupt:
        print(f"\n{GR}Interrupted.{X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
