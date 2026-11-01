# Gravion Secret Sniper

> Leak detection for credentials — static analysis, entropy analysis and **live credential verification**.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-authorized%20use%20only-orange.svg)](#legal)

**Author:** Priyanshu Kumar Thakur ([@pkt_143](https://t.me/pkt_143)) · **Alias:** Gravion
**GitHub:** [gravion-ux/gravion-secret-sniper](https://github.com/gravion-ux/gravion-secret-sniper)

---

## What it does

Gravion Secret Sniper finds leaked API keys, tokens, passwords and private keys across
files, directories, **archives**, **encoded payloads** and **full git history** — then
optionally contacts each credential's own provider to find out whether it is still **live**.

| Capability | Detail |
|---|---|
| **Pattern detection** | 120+ rules across cloud, AI/LLM, payments, CI/CD, databases, messaging and SaaS |
| **Structural validation** | AWS key prefixes, JWT header/payload decoding, Stripe/OpenAI/Slack/Supabase shapes — false positives die early |
| **Entropy analysis** | Shannon-entropy sweep with keyword proximity scoring and placeholder rejection |
| **Encoded payload analysis** | Recursively decodes base64/hex blobs and scans the plaintext inside them |
| **Archive expansion** | Walks `.zip`, `.tar`, `.gz`, `.whl`, `.jar` and friends, then scans each member |
| **Git history** | Scans every commit and every ref, including deleted secrets |
| **Live verification** | `--verify` asks the issuer (GitHub, Stripe, Slack, AWS-style providers…) if the credential still works |
| **Multi-format export** | SARIF 2.1.0, JSON, CSV and a self-contained HTML report |
| **Baseline diffing** | `--baseline` reports only secrets that are *new* since a previous scan |
| **CI friendly** | `--fail-on CRITICAL` exits non-zero; SARIF uploads directly to code scanning |

**Zero required dependencies.** The scanner runs on a bare Python 3.9+ install.
`requests` is optional and only needed for live verification.

---

## Install

```bash
git clone https://github.com/gravion-ux/gravion-secret-sniper.git
cd gravion-secret-sniper
python gravion_secret_sniper.py selftest
```

Optional — live verification:

```bash
pip install requests
```

---

## Usage

### Scan

```bash
# a single file
python gravion_secret_sniper.py scan .env

# a whole project
python gravion_secret_sniper.py scan ./my-project

# a git repo, including every commit and deleted secrets
python gravion_secret_sniper.py scan ./my-repo --history

# an archive
python gravion_secret_sniper.py scan bundle.zip

# piped content
cat config.yaml | python gravion_secret_sniper.py scan -

# only the categories you care about, with a stricter severity floor
python gravion_secret_sniper.py scan ./repo --only aws,github,stripe --min-severity HIGH
```

### Live verification

```bash
python gravion_secret_sniper.py scan ./repo --verify
```

```
>> Live verification (contacting each credential's provider)
  LIVE    GitHub PAT (classic)     provider accepted the credential (HTTP 200)
  DEAD    Slack Bot Token          provider rejected the credential (HTTP 401)
  UNKNOWN Google / Gemini API Key  unexpected HTTP 404
```

Only the credential's **own issuer** is contacted — never a third party, never an
exploitation attempt. Each provider is asked a single "is this token still valid?" question.

### CI integration

```bash
# fail the build on any critical finding
python gravion_secret_sniper.py scan . --fail-on CRITICAL

# emit SARIF for GitHub code scanning
python gravion_secret_sniper.py scan . -e sarif -o results.sarif
```

```yaml
# .github/workflows/secret-scan.yml
- name: Scan for leaked secrets
  run: python gravion_secret_sniper.py scan . --fail-on CRITICAL -e sarif -o results.sarif
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

### Manage scans

```bash
python gravion_secret_sniper.py list                  # all saved scans
python gravion_secret_sniper.py show scan_20260101    # display one
python gravion_secret_sniper.py export scan_20260101 -f html
python gravion_secret_sniper.py clear scan_20260101   # delete one
```

### Allowlist

```bash
python gravion_secret_sniper.py ignore list
python gravion_secret_sniper.py ignore add "Generic Password"
python gravion_secret_sniper.py ignore add regex:^AKIAEXAMPLE
python gravion_secret_sniper.py ignore remove "Generic Password"
```

A raw secret passed to `ignore add` is stored as a **SHA-256 fingerprint**, never in
cleartext. The global allowlist lives at `~/.gravion_sniper/allowlist`; a project-local
`.gravionignore` can also hold path patterns to skip entirely.

---

## Interactive mode

Run with no subcommand for a menu:

```
[1] Scan a file            [8] Show a saved scan
[2] Scan a directory       [9] Clear a saved scan
[3] Scan a git repo        [10] Manage allowlist
[4] Scan a git repo (history) [11] Verify credentials in a saved scan
[5] Scan from stdin        [12] Run self-test
[6] Export a saved scan    [13] Exit
[7] List saved scans
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
- **Bounded resources.** File size caps, archive entry caps and decompression limits
  prevent zip-bomb style hangs.
- **Redaction by default.** Pass `--no-redact` only when you explicitly need the raw
  value on screen.

---

## Testing

```bash
python gravion_secret_sniper.py selftest    # 25 engine assertions
python smoke_test.py                         # 26 end-to-end CLI checks
```

The self-test asserts that 17 known credential formats are detected and that 8
common false-positive sources (placeholders, docs, hashes, UUIDs, ordinary code)
stay silent. The smoke test covers SARIF/JSON/CSV/HTML export, archive expansion,
git-history scanning, baseline diffing, `--fail-on` exit codes and the guarantee that
raw secrets never reach disk. Fixtures are generated at runtime — no credential-shaped
string is committed to this repository.

---

## Legal

Use this tool **only** on systems you own or have explicit written authorisation to
audit. Scanning third-party infrastructure without permission may be unlawful. If you
find a leaked credential that is not yours, report it to the owning organisation rather
than exploiting it.

---

## License

MIT © Priyanshu Kumar Thakur ([@pkt_143](https://t.me/pkt_143))
