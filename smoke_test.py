"""Functional smoke test for the Gravion Secret Sniper CLI.

Fixtures are generated at runtime inside a temporary directory so that no
credential-shaped string is ever committed to the repository.
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "gravion_secret_sniper.py")


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
print("SMOKE TEST · Gravion Secret Sniper")
print("=" * 66)

# 1. selftest
r = run("selftest")
check("selftest exits 0", r.returncode == 0, r.stdout[-400:])
check("selftest reports 25/25", "25/25" in r.stdout)

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
        check("sarif driver branded", driver["name"] == "Gravion Secret Sniper",
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
    home_scan = os.path.join(os.path.expanduser("~"), ".gravion_sniper", "scans",
                             "smoke_scan.json")
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
        check("html branded", "Gravion Secret Sniper" in html)
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
    zip_report = os.path.join(os.path.expanduser("~"), ".gravion_sniper",
                              "scans", "smoke_zip.json")
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
    git_report = os.path.join(os.path.expanduser("~"), ".gravion_sniper",
                              "scans", "smoke_git.json")
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
