<div align="center">

<img src="assets/key-hunter-logo.svg" alt="Key Hunter emblem — a hooded warden wielding a glowing key before a vault keyhole" width="220" />

# 🗝️ Key Hunter

### _Guardian of Secrets · Keeper of Configs_

**Find the leaked key before someone else does. Keep your API keys safe and your configs correct.**

[![Go](https://img.shields.io/badge/Go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Built With AI](https://img.shields.io/badge/%23BuiltWithAI-🤖-8A2BE2)](#-built-with-ai)
[![Website](https://img.shields.io/badge/Website-skymindautomation.com-1b2748?logo=googlechrome&logoColor=white)](https://skymindautomation.com)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?logo=buymeacoffee&logoColor=black)](https://www.buymeacoffee.com/skymindautomation)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](../../pulls)

</div>

---

## 🔐 What is Key Hunter?

**Key Hunter** (`key_hunter`) is a single-binary Go CLI for secret-hunting and light OSINT recon. It crawls a target, follows the trail through archives and source maps, sniffs out high-entropy secrets, and can even **confirm which keys are actually live** — all in one hunt.

```text
    ██╗  ██╗███████╗██╗   ██╗   ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
    ██║ ██╔╝██╔════╝╚██╗ ██╔╝   ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    █████╔╝ █████╗   ╚████╔╝    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔═██╗ ██╔══╝    ╚██╔╝     ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██║  ██╗███████╗   ██║      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝  ╚═╝╚══════╝   ╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
         o═══⊐  GUARDIAN OF SECRETS · KEEPER OF CONFIGS  ⊏═══o
```

---

## ⚡ The Hunt — three phases

| Phase | Power | What it does |
|:-----:|:------|:-------------|
| 🛰️ **I · Recon** | Seed the hunt | Pull seed URLs & in-scope hosts from the **Wayback Machine**, **OTX AlienVault**, **crt.sh**, and the target's own robots.txt/sitemap — reaching archived, unlinked, and sibling-subdomain pages a live crawl never sees. |
| 🎯 **II · Detect** | Sweep everything | Regex-match **40+ secret types**, fetch and scan **JS source maps'** original source, flag exposed **`.git`/`.env`** files, and run **Shannon-entropy** detection for secrets that match no known prefix. |
| 🔥 **III · Validate** | Prove the threat | Confirm which keys are **actually live** with documented, read-only provider calls — real dangers separated from dead strings _(TruffleHog-style verified mode)_. |

Optional second-pass **AI classification** (Ollama · OpenAI · Anthropic · Gemini) filters placeholders and examples from real keys.

---

## 🧰 What it detects

<details>
<summary><b>40+ secret patterns</b> — click to expand</summary>

- **AI / ML** — OpenAI (legacy + project), Anthropic Claude, Google AI Studio, Hugging Face, Replicate, Perplexity
- **Cloud & Infra** — AWS access/secret keys, Azure Storage, GCP service-account keys, DigitalOcean, Terraform Cloud, CircleCI
- **Source control** — GitHub PAT & fine-grained tokens, GitLab tokens
- **Payments & comms** — Stripe, Slack, Discord, Mailgun, Twilio, SendGrid, Shopify, Square
- **Registries & tooling** — npm, Docker Hub, PyPI, Postman
- **Observability & search** — New Relic, Datadog, Algolia, Cloudflare, Heroku
- **Generic** — API-key patterns, JWTs, Bearer tokens, PEM private keys
- **Heuristic** — Shannon-entropy high-entropy strings, exposed `.git` repositories & sensitive files

</details>

---

## 🚀 Quick start

```bash
# Clone & build
git clone https://github.com/Parrot-R/api-key-hunter.git
cd api-key-hunter
go build -o key_hunter .

# Basic hunt
./key_hunter --url https://example.com

# Full secret-hunt: OSINT seeds + entropy + source maps + live validation
./key_hunter --url https://example.com --wayback --otx --entropy --validate --formats json,html

# Reports in every format
./key_hunter --url https://example.com --formats json,csv,html,sarif --output report
```

---

## ⚙️ Configuration

Drive an entire scan from a YAML file — CLI flags still override individual values (`default < config file < flag`):

```yaml
url: https://example.com
depth: 4
formats: [json, html, sarif]
domains: [example.com, cdn.example.com]

entropy:
  enabled: true
  threshold: 4.0

sources:
  wayback: true
  otx: true

ai:
  provider: anthropic          # or ANTHROPIC_API_KEY env var
```

```bash
./key_hunter --config config.yaml
```

<details>
<summary><b>Key flags</b></summary>

| Flag | Purpose |
|:-----|:--------|
| `--url` | Target URL _(required unless set in `--config`)_ |
| `--formats` | `json,csv,html,sarif` (default `json`) |
| `--depth`, `--domains`, `--parallel`, `--delay` | Crawl scope & pacing |
| `--random-delay`, `--proxies`, `--ignore-robots`, `--include-ext` | Stealth / rate-limit |
| `--wayback`, `--otx`, `--otx-key`, `--crtsh`, `--subdomain-scope` | OSINT recon |
| `--active-recon` 🔒 | Probe sensitive paths _(authorization required)_ |
| `--validate` 🔒 | Confirm keys live against providers _(authorization required)_ |
| `--entropy`, `--entropy-threshold` | High-entropy detection |
| `--ai`, `--ai-model`, `--ai-key` | AI classification |

</details>

---

## 📊 Output

JSON (full detail, raw values for remediation), plus shareable **CSV**, **HTML**, and **SARIF** reports (masked values only, with a `LIVE` marker on confirmed keys). Auto-saves periodically and on `Ctrl+C`.

---

## 🛡️ Responsible use

> Key Hunter is a **defensive** tool for finding *your own* leaked secrets and for **authorized** security testing.
>
> `--active-recon` (probes sensitive paths) and `--validate` (uses a discovered credential against its provider) are **off by default**, each gated behind an authorization banner. Only enable them against targets you own or are explicitly authorized to test.

---

## 👥 Authors

- 🦜 **parrot-r** — [skymindautomation@gmail.com](mailto:skymindautomation@gmail.com) · [skymindautomation.com](https://skymindautomation.com)
- 🤖 **Claude** — pair-programmed with [Claude Code](https://claude.com/claude-code)

---

## ☕ Support

If Key Hunter saved you from a leaked key, consider fueling the next hunt:

<div align="center">

[![Buy Me a Coffee](https://img.shields.io/badge/☕%20Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buymeacoffee&logoColor=black)](https://www.buymeacoffee.com/skymindautomation)
[![Website](https://img.shields.io/badge/🌐%20skymindautomation.com-1b2748?style=for-the-badge)](https://skymindautomation.com)

</div>

---

## 🤖 Built With AI

<div align="center">

Designed & built with AI pair-programming. &nbsp;**#BuiltWithAI** 🤖💪

_🗝️ Hunt every leaked key · Guard every config · Keep your keys safe 🔐_

</div>
