# Secret Sniper

> Leak detection for credentials — static analysis, entropy analysis, **single-site scanning** and **live credential verification**.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-authorized%20use%20only-orange.svg)](#legal)

**Author:** Priyanshu Kumar Thakur ([@pkt_143](https://t.me/pkt_143)) · **Alias:** Gravion
**GitHub:** [gravion-ux/secret-sniper](https://github.com/gravion-ux/secret-sniper)

---

## 30-second quick start

```bash
git clone https://github.com/gravion-ux/secret-sniper.git
cd secret-sniper
python secret_sniper.py selftest        # prove the engine works
python secret_sniper.py help            # every command on one screen
python secret_sniper.py url https://target.tld --crawl 3 --verify
```

No dependencies required — Python 3.9+ is enough. `requests` is optional and only needed
for live verification.

---

## What it does

Secret Sniper finds leaked API keys, tokens, passwords and private keys across files,
directories, **archives**, **encoded payloads**, **full git history** and **live websites** —
then optionally contacts each credential's own provider to find out whether it is still **live**.

| Capability | Detail |
|---|---|
| **Single-site scanning** | `url` fetches a page, scans the HTML, every inline script and every referenced JS/CSS bundle, then probes sensitive paths |
| **Pattern detection** | 120+ rules across cloud, AI/LLM, payments, CI/CD, databases, messaging and SaaS |
| **Structural validation** | AWS key prefixes, JWT header/payload decoding, Stripe/OpenAI/Slack/Supabase shapes — false positives die early |
| **Entropy analysis** | Shannon-entropy sweep with keyword proximity scoring and placeholder rejection |
| **Encoded payload analysis** | Recursively decodes base64/hex blobs and scans the plaintext inside them |
| **Archive expansion** | Walks `.zip`, `.tar`, `.gz`, `.whl`, `.jar` and friends, then scans each member |
| **Git history** | Scans every commit and every ref, including deleted secrets |
| **Live verification** | `--verify` asks the issuer (GitHub, Stripe, Slack, AWS-style providers…) if the credential still works — body-aware, so a `200 OK` with an error body counts as dead |
| **Multi-format export** | SARIF 2.1.0, JSON, CSV and a self-contained HTML report |
| **Baseline diffing** | `--baseline` reports only secrets that are *new* since a previous scan |
| **CI friendly** | `--fail-on CRITICAL` exits non-zero; SARIF uploads directly to code scanning |
| **One-screen help** | `help` prints the whole command reference with an ASCII banner — no flag memorising |

---

## The `help` command

Run it with no arguments and you get the full reference, exactly like `nmap` or `sqlmap`:

```
  ███████ ███████ ███████ ███████ ███████ ███████
  ██      ██      ██      ██  ██ ██        ██
  ███████ █████   ██      ███████ █████     ██
       ██ ██      ██      ██  ██ ██        ██
  ███████ ███████ ███████ ██   ██ ███████   ██
  ██      ██   ██ ███████ ███████ ███████ ███████
  ██      ███  ██   ██   ██  ██ ██      ██  ██
  ███████ ████ ██   ██   ███████ █████   ███████
       ██ ██ ███   ██   ██      ██      ██  ██
  ███████ ██  ██ ███████ ██      ███████ ██   ██
```

`help` lists every command grouped by purpose, with copy-paste examples, the live-verification
verdicts and the exit codes. `help <command>` prints the detail for a single command:

```bash
python secret_sniper.py help
python secret_sniper.py help url
```

---

## Scan a single website

This is the bug-hunter's shortcut — point it at a site and it does the boring part for you:

```bash
# page + every JS/CSS bundle it loads + sensitive-path recon
python secret_sniper.py url https://target.tld

# also follow 5 pages on the same host
python secret_sniper.py url https://target.tld --crawl 5

# live-check every credential it finds
python secret_sniper.py url https://target.tld --crawl 3 --verify

# save it and export SARIF for code scanning
python secret_sniper.py url https://target.tld --name target -e sarif -o target.sarif
```

What it does, in order:

1. **Fetches the page** with a browser-like User-Agent, following redirects.
2. **Scans the HTML** — inline scripts, `data-*` attributes, comments and embedded JSON.
3. **Scans every inline `<script>` block** separately.
4. **Downloads the referenced JavaScript and CSS** (default cap: 25 bundles, 5 MB each) and
   scans them. This is where front-end keys usually hide.
5. **Crawls** up to `--crawl N` same-host pages, with a shared asset budget.
6. **Probes sensitive paths** — `/.env`, `/.git/config`, `/.DS_Store`, `/config.json`,
   `/package.json`, `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`. A readable
   `/.env` is reported as an exposure, and its contents are scanned for credentials too.

Everything is read-only: GET requests only, no authentication headers, no exploitation,
no bruteforce. Findings land in a normal saved scan, so `list`, `show`, `export` and
`verify` all work on a URL scan exactly as they do on a folder scan.

Useful flags: `--crawl N`, `--no-recon`, `--max-assets N`, `--timeout S`,
`--user-agent "..."`, `--header "Name: value"` (repeatable), `--only aws,stripe`,
`--min-severity HIGH`, `--verify`, `--fail-on CRITICAL`, `--name`, `-e/--export`, `-o/--out`.

---

## Scan files, folders and git history

```bash
# a single file
python secret_sniper.py scan .env

# a whole project
python secret_sniper.py scan ./my-project

# a git repo, including every commit and deleted secrets
python secret_sniper.py scan ./my-repo --history

# an archive
python secret_sniper.py scan bundle.zip

# piped content
cat config.yaml | python secret_sniper.py scan -

# only the categories you care about, with a stricter severity floor
python secret_sniper.py scan ./repo --only aws,github,stripe --min-severity HIGH
```

---

## Live verification

```bash
python secret_sniper.py scan ./repo --verify
python secret_sniper.py verify scan_20260101
```

```
>> Live verification (contacting each credential's provider)
  LIVE    GitHub PAT (classic)     provider accepted the credential (HTTP 200)
  DEAD    Slack Bot Token          provider rejected the credential (HTTP 200 with an error body)
  SKIPPED Discord Bot Token        no live check available for this pattern
  UNKNOWN Google / Gemini API Key  unexpected HTTP 404
```

| Verdict | Meaning |
|---|---|
| `LIVE` | the provider accepted the credential |
| `DEAD` | the provider rejected it |
| `SKIPPED` | no live check exists for that provider — the value was never sent anywhere |
| `UNKNOWN` | the check could not complete (network error, unexpected status) |

Only the credential's **own issuer** is contacted — never a third party, never an
exploitation attempt. Each provider is asked a single "is this token still valid?" question.
Providers that answer `HTTP 200` with an error body (Slack's `auth.test` returns
`{"ok": false}`) are judged by the body, so dead tokens are never reported as live.

---

## CI integration

```bash
# fail the build on any critical finding
python secret_sniper.py scan . --fail-on CRITICAL

# emit SARIF for GitHub code scanning
python secret_sniper.py scan . -e sarif -o results.sarif
```

```yaml
# .github/workflows/secret-scan.yml
- name: Scan for leaked secrets
  run: python secret_sniper.py scan . --fail-on CRITICAL -e sarif -o results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

> **Turn on CI for this repository in one edit.** The complete workflow is committed as
> [`.github/secret-scan.workflow.yml`](.github/secret-scan.workflow.yml). GitHub only runs
> workflows that live under `.github/workflows/`, so move that file there — on GitHub, open
> the file → **Rename** → set the path to `.github/workflows/secret-scan.yml`. It runs three
> jobs: engine self-test, CLI smoke test, and a self-scan that uploads SARIF to code
> scanning. Cloning this repo and pushing it also brings the workflow up unchanged.

---

## Manage scans

```bash
python secret_sniper.py list                  # all saved scans
python secret_sniper.py show scan_20260101    # display one
python secret_sniper.py export scan_20260101 -f html
python secret_sniper.py clear scan_20260101   # delete one
```

### Allowlist

```bash
python secret_sniper.py ignore list
python secret_sniper.py ignore add "Generic Password"
python secret_sniper.py ignore add regex:^AKIAEXAMPLE
python secret_sniper.py ignore remove "Generic Password"
```

A raw secret passed to `ignore add` is stored as a **SHA-256 fingerprint**, never in
cleartext. The global allowlist lives at `~/.secret_sniper/allowlist`; a project-local
`.secretignore` can also hold path patterns to skip entirely.

---

## Interactive mode

Prefer a menu? `interactive` opens it:

```
[1] Scan a file            [8] Show a saved scan
[2] Scan a directory       [9] Clear a saved scan
[3] Scan a git repo        [10] Manage allowlist
[4] Scan a git repo (history) [11] Verify credentials in a saved scan
[5] Scan from stdin        [12] Run self-test
[6] Export a saved scan    [13] Scan a website (URL)
[7] List saved scans       [14] Show the command reference
                            [15] Exit
```

---

## Detection rules

| Category | Examples |
|---|---|
| `aws` | Access key IDs, secret access keys, MWS keys, session tokens |
| `google` / `gcp` / `firebase` | API keys, OAuth client secrets, service-account JSON, FCM keys |
| `azure` | Storage account keys, SAS tokens, AD client secrets |
| `github` / `gitlab` / `bitbucket` | Classic, fine-grained, OAuth, App and runner tokens |
| `openai` / `anthropic` / `google` / `groq` / `mistral` / `cohere` / `huggingface` | LLM provider keys |
| `stripe` / `square` / `braintree` / `paypal` / `razorpay` | Payment processor secrets |
| `slack` / `discord` / `telegram` | Bot tokens and webhooks |
| `private-key` | PEM, OpenSSH, PGP, PKCS#12 — full multi-line block detection |
| `jwt` | Tokens with real header/payload decoding |
| `database` | Postgres, MySQL, MongoDB, Redis, AMQP, Supabase, Snowflake |
| `npm` / `pypi` / `docker` | Package registry tokens |
| `github`-adjacent CI | CircleCI, Artifactory, Codecov, Azure DevOps PATs |
| `generic` | Keyword-adjacent API keys, secrets, passwords and bearer tokens |

Use `--only` to scope a scan to specific categories.

---

## Safety design

- **Raw secret values are never written to disk.** Reports persist only the redacted
  form plus a SHA-256 fingerprint, so a saved scan is safe to share.
- **No exploitation.** The tool only detects and, on request, *validates* that a
  credential is live. It never uses a credential against a protected system.
- **Read-only web scanning.** The `url` command issues GET requests only, sends no
  authentication headers, and never brute-forces or fuzzes anything.
- **Bounded resources.** File size caps, archive entry caps, decompression limits and
  asset/time budgets prevent zip-bomb style hangs.
- **Redaction by default.** Pass `--no-redact` only when you explicitly need the raw
  value on screen.

---

## Testing

```bash
python secret_sniper.py selftest    # 61 engine assertions
python smoke_test.py                 # 47 end-to-end CLI checks
```

The self-test asserts that 17 known credential formats are detected, that 8 common
false-positive sources (placeholders, docs, hashes, UUIDs, ordinary code) stay silent,
that the live-verification layer judges a provider's answer by its body as well as
its status code, and that the generic fallback rules tell a real credential apart
from a code identifier, a dotted property path and a provider object id. The smoke
test covers SARIF/JSON/CSV/HTML export, archive expansion, git-history scanning,
baseline diffing, `--fail-on` exit codes, the `help` screen, a full single-site scan
against a local test server (asset discovery, crawling, sensitive-path recon), the
zero-finding report path and the guarantee that raw secrets never reach disk.
Fixtures are generated at runtime — no credential-shaped string is committed to this
repository.

---

## Legal

Use this tool **only** on systems you own or have explicit written authorisation to
audit. Scanning third-party infrastructure without permission may be unlawful. If you
find a leaked credential that is not yours, report it to the owning organisation rather
than exploiting it.

---

## License

MIT © Priyanshu Kumar Thakur ([@pkt_143](https://t.me/pkt_143))
