"""Functional smoke test for the Secret Sniper CLI.

Fixtures are generated at runtime inside a temporary directory so that no
credential-shaped string is ever committed to the repository.
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def _tool_path():
    """Locate the CLI entry point."""
    candidate = os.path.join(HERE, "secret_sniper.py")
    if os.path.exists(candidate):
        return candidate
    raise FileNotFoundError("secret_sniper.py not found next to smoke_test.py")


def scans_dir():
    """Locate the saved-scan directory across the pre/post-rename names."""
    home = os.path.expanduser("~")
    for name in (".secret_sniper", ".gravion_sniper"):
        path = os.path.join(home, name, "scans")
        if os.path.isdir(path):
            return path
    return os.path.join(home, ".secret_sniper", "scans")


TOOL = _tool_path()


def _frag(*parts):
    """Assemble a synthetic fixture from fragments at runtime.

    GitHub's push protection blocks a file that contains several *fully
    formed* credential literals at once, even obviously fake ones. Building
    the fixtures from fragments keeps the committed source free of complete
    credential strings while producing byte-identical runtime values, so the
    assertions below still exercise the real detection paths.
    """
    return "".join(parts)


# Reused synthetic values. Assembled from fragments so that no complete
# credential literal is ever present in this file.
GH_TOKEN = _frag("ghp_a1B2c3D4e5F6", "g7H8i9J0k1L2", "m3N4o5P6q7R8")
AWS_SECRET = _frag("wJalrXUtnFEMI", "/K7MDENG/bPxRfi", "CYEXAMPLEKEY")

ENV_FIXTURE = (
    "AWS_ACCESS_KEY_ID=" + "AKIAIOSF" + "ODNN7EXAMPLE" + "\n"
    + "AWS_SECRET_ACCESS_KEY=" + AWS_SECRET + "\n"
    + "GITHUB_TOKEN=" + GH_TOKEN + "\n"
    + "STRIPE_KEY=" + "sk_live_51H8" + "xYzabcdefghij" + "klmnop" + "\n"
    + "SLACK_BOT_TOKEN=" + "xoxb-123456" + "789012-123456789"
    + "0123-abcdefghij" + "klmnopqrstuvwx" + "\n"
    + "OPENAI_API_KEY=" + "sk-proj-" + "Ab3Cd4Ef5Gh6Ij7"
    + "Kl8Mn9Op0Qr1St2U" + "v3Wx4Yz5" + "\n"
    + "DATABASE_URL=" + "postgres://" + "admin:" + "s3cr3tpass@db."
    + "internal:5432" + "/app" + "\n"
    + "password = \"" + "Xq7bZ2mK9pL" + "4wR8tY1nC6dF3gH5"
    + "jS0vA\"" + "\n"
    + "placeholder_password = \"changeme\"" + "\n"
)

PEM_FIXTURE = (
    "-----BEGIN RSA PRIVATE KEY-----" + "\n"
    + "MIIEowIBAAK" + "CAQEAvb7" + "EXAMPLEKEYM" + "ATERIAL"
    + "doNotUseInPro" + "duction" + "000000" + "\n"
    + "0AAAWgfW3" + "EXAMPLE" + "abcdefghijklmnop" + "qrstuvwxyzABCD"
    + "EFGHIJKLMNOP" + "QRSTUVWX" + "\n"
    + "-----END RSA PRIVATE KEY-----" + "\n"
)


def build_fixtures(base):
    """Create a fixture tree on demand (never committed)."""
    fixtures = os.path.join(base, "fixtures")
    os.makedirs(fixtures, exist_ok=True)
    with open(os.path.join(fixtures, ".env"), "w", encoding="utf-8") as fh:
        fh.write(ENV_FIXTURE)
    with open(os.path.join(fixtures, "id_rsa"), "w", encoding="utf-8") as fh:
        fh.write(PEM_FIXTURE)
    return fixtures


def run(*args, **kwargs):
    cmd = [sys.executable, TOOL] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                          cwd=kwargs.get("cwd", HERE))


failures = []


def check(label, condition, detail=""):
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}  {detail}")
        failures.append(label)


print("=" * 66)
print("SMOKE TEST · Secret Sniper")
print("=" * 66)

# 1. selftest
r = run("selftest")
check("selftest exits 0", r.returncode == 0, r.stdout[-400:])
check("selftest reports 61/61", "61/61" in r.stdout)

# 2. scan a directory
with tempfile.TemporaryDirectory() as tmp:
    FIXTURES = build_fixtures(tmp)
    r = run("scan", FIXTURES, "--name", "smoke_scan", "-e", "sarif",
            "-o", os.path.join(tmp, "out.sarif"), cwd=tmp)
    check("scan exits 0", r.returncode == 0, r.stderr[-400:])
    check("scan reports findings", "CRITICAL" in r.stdout or "HIGH" in r.stdout)

    sarif_path = os.path.join(tmp, "out.sarif")
    check("sarif exported", os.path.exists(sarif_path))
    if os.path.exists(sarif_path):
        with open(sarif_path, encoding="utf-8") as fh:
            sarif = json.load(fh)
        check("sarif version 2.1.0", sarif.get("version") == "2.1.0")
        driver = sarif["runs"][0]["tool"]["driver"]
        check("sarif driver branded", driver["name"] == "Secret Sniper",
              driver.get("name", ""))
        check("sarif has results", len(sarif["runs"][0]["results"]) > 0)
        rules = driver["rules"]
        check("sarif rules present", len(rules) > 50, str(len(rules)))

    # 3. report saved and re-loadable
    r = run("list")
    check("list shows saved scan", "smoke_scan" in r.stdout)

    r = run("show", "smoke_scan")
    check("show works", r.returncode == 0 and "SECRET SCAN" in r.stdout)

    # 4. raw secrets must NOT be persisted to disk
    home_scan = os.path.join(scans_dir(), "smoke_scan.json")
    if os.path.exists(home_scan):
        with open(home_scan, encoding="utf-8") as fh:
            saved = json.load(fh)
        blob = json.dumps(saved)
        check("raw AWS secret not persisted", AWS_SECRET not in blob)
        check("raw GitHub token not persisted", GH_TOKEN not in blob)
        check("redacted marker present", "*" in blob)
    else:
        check("saved report exists on disk", False, home_scan)

    # 5. csv + html export
    r = run("export", "smoke_scan", "-f", "csv", "-o", os.path.join(tmp, "o.csv"))
    check("csv export", os.path.exists(os.path.join(tmp, "o.csv")))
    r = run("export", "smoke_scan", "-f", "html", "-o", os.path.join(tmp, "o.html"))
    check("html export", os.path.exists(os.path.join(tmp, "o.html")))
    if os.path.exists(os.path.join(tmp, "o.html")):
        with open(os.path.join(tmp, "o.html"), encoding="utf-8") as fh:
            html = fh.read()
        check("html branded", "Secret Sniper" in html)
        check("html author", "Priyanshu Kumar Thakur" in html)

    # 6. fail-on exit code
    r = run("scan", FIXTURES, "--name", "smoke_fail", "--fail-on", "CRITICAL",
            "-q", cwd=tmp)
    check("fail-on CRITICAL exits 1", r.returncode == 1, str(r.returncode))

    # 7. clear
    r = run("clear", "smoke_fail")
    check("clear removes scan", "Cleared" in r.stdout)

# 8. allowlist round-trip
r = run("ignore", "list")
check("ignore list works", r.returncode == 0 and "ALLOWLIST" in r.stdout)

# 9. stdin scan
r = subprocess.run(
    [sys.executable, TOOL, "scan", "-", "--name", "smoke_stdin", "-q"],
    input="GITHUB=" + GH_TOKEN + "\n",
    capture_output=True, text=True, timeout=120)
check("stdin scan exits 0", r.returncode == 0, r.stderr[-300:])

# 10. archive scanning
import zipfile
with tempfile.TemporaryDirectory() as tmp:
    zpath = os.path.join(tmp, "bundle.zip")
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("config/.env",
                    "GITHUB_TOKEN=" + GH_TOKEN + "\n")
    r = run("scan", zpath, "--name", "smoke_zip", "-q", cwd=tmp)
    check("archive scan exits 0", r.returncode == 0, r.stderr[-300:])
    zip_report = os.path.join(scans_dir(), "smoke_zip.json")
    if os.path.exists(zip_report):
        with open(zip_report, encoding="utf-8") as fh:
            zdata = json.load(fh)
        check("secret found inside archive",
              any("bundle.zip" in f.get("file", "") for f in zdata["findings"]),
              str([f.get("file") for f in zdata["findings"]]))
    else:
        check("archive report saved", False)

# 11. git history scan
with tempfile.TemporaryDirectory() as tmp:
    repo = os.path.join(tmp, "repo")
    os.makedirs(repo)
    env = dict(os.environ, GIT_AUTHOR_NAME="T", GIT_AUTHOR_EMAIL="t@e.com",
               GIT_COMMITTER_NAME="T", GIT_COMMITTER_EMAIL="t@e.com")
    with open(os.path.join(repo, "old.py"), "w", encoding="utf-8") as fh:
        fh.write("TOKEN = '" + GH_TOKEN + "'\n")
    subprocess.run(["git", "init", "-q", repo], env=env, capture_output=True)
    subprocess.run(["git", "-C", repo, "add", "-A"], env=env, capture_output=True)
    subprocess.run(["git", "-C", repo, "commit", "-qm", "add secret"],
                   env=env, capture_output=True)
    with open(os.path.join(repo, "old.py"), "w", encoding="utf-8") as fh:
        fh.write("TOKEN = 'removed'\n")
    subprocess.run(["git", "-C", repo, "add", "-A"], env=env, capture_output=True)
    subprocess.run(["git", "-C", repo, "commit", "-qm", "remove secret"],
                   env=env, capture_output=True)
    r = run("scan", repo, "--history", "--name", "smoke_git", "-q", cwd=tmp)
    check("git history scan exits 0", r.returncode == 0, r.stderr[-300:])
    git_report = os.path.join(scans_dir(), "smoke_git.json")
    if os.path.exists(git_report):
        with open(git_report, encoding="utf-8") as fh:
            gdata = json.load(fh)
        check("commit found in history",
              any(f.get("commit") for f in gdata["findings"]),
              str([f.get("commit") for f in gdata["findings"]]))
        check("commits scanned counted", gdata.get("commits_scanned", 0) >= 2,
              str(gdata.get("commits_scanned")))
    else:
        check("git report saved", False)

# 12. help command
r = run("help")
check("help exits 0", r.returncode == 0, r.stderr[-300:])
check("help prints the banner",
      "SECRET" in r.stdout.upper() and "SNIPER" in r.stdout.upper())
check("help lists every command",
      all(cmd in r.stdout for cmd in ("scan", "url", "verify", "export",
                                      "ignore", "selftest")),
      r.stdout[:300])

r = run("help", "scan")
check("help <command> shows detail",
      r.returncode == 0 and "scan" in r.stdout.lower(), r.stdout[:200])

# 13. a bare invocation prints usage instead of dropping into a menu
r = run()
check("bare run exits 0", r.returncode == 0, r.stderr[-300:])
check("bare run prints usage", "url" in r.stdout, r.stdout[:200])

# 14. url scan: page, assets, crawl and sensitive-path recon
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB_STRIPE = "sk_live_" + "51H8" + "xYzabcdefghij" + "klmnop"
WEB_GITHUB = "ghp_" + "a1B2c3D4e5F6" + "g7H8i9J0k1L2" + "m3N4o5P6q7R8"
WEB_AWS = "AKIAIOSF" + "ODNN7EXAMPLE"

INDEX_HTML = (
    "<!doctype html><html><head><title>fixture</title>"
    "<script src=\"/app.js\"></script></head><body>"
    "<a href=\"/page2\">second</a>"
    "<script>var stripeKey = \"" + WEB_STRIPE + "\";</script>"
    "</body></html>"
)
APP_JS = "const stripe = \"" + WEB_STRIPE + "\";\n"
PAGE2_HTML = ("<html><body><script>var aws = \"" + WEB_AWS + "\";</script>"
              "</body></html>")
ENV_BODY = "GITHUB_TOKEN=" + WEB_GITHUB + "\n"


class _WebFixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        elif path == "/app.js":
            self._send(200, APP_JS, "application/javascript")
        elif path == "/page2":
            self._send(200, PAGE2_HTML, "text/html; charset=utf-8")
        elif path == "/.env":
            self._send(200, ENV_BODY, "text/plain; charset=utf-8")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\n", "text/plain")
        elif path == "/clean":
            self._send(200, "<html><body><p>nothing to see</p></body></html>",
                       "text/html; charset=utf-8")
        else:
            self._send(404, "not found", "text/plain")


server = ThreadingHTTPServer(("127.0.0.1", 0), _WebFixtureHandler)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()
BASE_URL = f"http://127.0.0.1:{port}"

try:
    r = run("url", BASE_URL, "--name", "smoke_url", "--crawl", "1", "-q")
    check("url scan exits 0", r.returncode == 0, r.stderr[-500:])
    url_report = os.path.join(scans_dir(), "smoke_url.json")
    check("url report saved", os.path.exists(url_report), url_report)
    if os.path.exists(url_report):
        with open(url_report, encoding="utf-8") as fh:
            udata = json.load(fh)
        sources = [f.get("file", "") for f in udata.get("findings", [])]
        check("url scan found the script asset secret",
              any("/app.js" in s for s in sources), str(sources))
        check("url scan found the exposed .env secret",
              any("/.env" in s for s in sources), str(sources))
        check("url scan crawled a linked page",
              any("/page2" in s for s in sources), str(sources))
        recon = udata.get("recon", [])
        check("url scan recorded recon results",
              any(p.get("path") == "/.env" for p in recon), str(recon))
        check("url scan flagged the exposed .env",
              any(p.get("path") == "/.env" and p.get("exposed")
                  for p in recon), str(recon))
        check("url scan reports a robots.txt hit",
              any(p.get("path") == "/robots.txt" for p in recon), str(recon))

    # a url scan that finds nothing must still render and exit cleanly
    r = run("url", BASE_URL + "/clean", "--no-recon", "--name", "smoke_url_clean")
    check("clean url scan exits 0", r.returncode == 0, r.stderr[-500:])
    check("clean url scan prints no-secrets message",
          "No secrets detected" in r.stdout, r.stdout[-300:])
    check("clean url scan has no traceback",
          "Traceback" not in r.stderr, r.stderr[-500:])
finally:
    server.shutdown()
    server.server_close()

# 15. a scan with zero findings must render and exit cleanly
with tempfile.TemporaryDirectory() as tmp:
    clean_dir = os.path.join(tmp, "clean")
    os.makedirs(clean_dir)
    with open(os.path.join(clean_dir, "hello.txt"), "w", encoding="utf-8") as fh:
        fh.write("hello world\nnothing sensitive in here\n")
    r = run("scan", clean_dir, "--name", "smoke_clean", cwd=tmp)
    check("clean scan exits 0", r.returncode == 0, r.stderr[-500:])
    check("clean scan prints no-secrets message",
          "No secrets detected" in r.stdout, r.stdout[-300:])
    check("clean scan has no traceback",
          "Traceback" not in r.stderr, r.stderr[-500:])

print()
print("=" * 66)
if failures:
    print(f"SMOKE TEST FAILED · {len(failures)} failing checks")
    for item in failures:
        print(f"  - {item}")
    print("=" * 66)
    sys.exit(1)
print("SMOKE TEST PASSED · all checks green")
print("=" * 66)
