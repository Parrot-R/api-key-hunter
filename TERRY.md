# TERRY.md

This file provides guidance to Terry Code when working with code in this repository.

## What this is

Key Hunter (`key_hunter`) is a single-binary Go CLI for secret-hunting / light OSINT recon. It runs in **three phases** around a `gocolly` crawl:

1. **Seed/recon phase** (optional) — before crawling, gather extra seed URLs and in-scope hosts from passive OSINT sources (Wayback Machine, OTX AlienVault, crt.sh) and the target's own robots.txt/sitemap; optionally probe a sensitive-path wordlist (`.env`, `.git/config`, config backups).
2. **Crawl phase** — visit the target plus all seeds, following `<a>`/`<script src>`, and scan every page/script/response body against regex patterns for leaked keys (OpenAI, Anthropic, AWS, GitHub, Stripe, Slack, npm, Docker Hub, and many more). This phase also **fetches source maps** (`//# sourceMappingURL=`) and scans their embedded original source, flags **exposed `.git`/sensitive files**, and (optionally) runs **Shannon-entropy detection** for high-entropy secrets that match no known prefix. Optionally each detection is sent to an LLM (Ollama, OpenAI, Anthropic, Gemini) for a second-pass classification (`real_key`/`placeholder`/`example`/`documentation`/`false_positive`).
3. **Validation phase** (optional) — confirm which found keys are actually *live* by issuing a documented read-only request to each provider's API (TruffleHog-style verified mode).

Results can be written as JSON, CSV, HTML, and/or SARIF, with periodic auto-save and save-on-interrupt (Ctrl+C).

The program is a handful of files in `package main` at the repo root (no subpackages). There is no test suite, no CI config, no Makefile, and no Dockerfile in this repo currently.

**Two features are intrusive and off by default, each gated behind its own flag and an authorization banner** (same posture as `--ignore-robots`): `--active-recon` (probes sensitive paths on the target) and `--validate` (uses a discovered credential against its provider). Only enable them against targets you're authorized to test.

## Commands

```bash
# Build
go build -o key_hunter .

# Run directly without building
go run . --url https://example.com

# Format (run before committing)
gofmt -l .          # list files needing formatting
gofmt -w .           # apply formatting

# Vet
go vet ./...

# Tidy/verify dependencies
go mod tidy
go mod verify
```

There are no `_test.go` files, so `go test ./...` currently has nothing to run. If you add tests, `go test ./...` and `go test -run TestName ./...` will work normally since this is a standard `go.mod` module (`module key_hunter`, Go 1.24).

### Running a scan

```bash
# Basic crawl, no AI verification
./key_hunter --url https://example.com

# Restrict crawl to specific domains, increase depth
./key_hunter --url https://example.com --domains example.com,cdn.example.com --depth 5

# Multiple output formats
./key_hunter --url https://example.com --formats json,csv,html,sarif --output report

# Only scan JS/config-like files, add jitter, rotate through proxies
./key_hunter --url https://example.com --include-ext .js,.json,.env --random-delay 2 --proxies http://proxy1:8080,http://proxy2:8080

# Full secret-hunting run: OSINT seeds + entropy + source maps (always on) + live validation
./key_hunter --url https://example.com --wayback --otx --entropy --validate --formats json,html

# Active recon (authorization required): probe .env/.git/config-backup paths across discovered subdomains
./key_hunter --url https://example.com --crtsh --subdomain-scope --active-recon

# Driven entirely by a config file (CLI flags still override individual values)
./key_hunter --config config.yaml

# With AI verification (Ollama, local)
./key_hunter --url https://example.com --ai ollama --ai-model llama3.2

# With AI verification (cloud provider, key via flag or env var)
./key_hunter --url https://example.com --ai openai --ai-key sk-xxx --ai-model gpt-4o-mini
./key_hunter --url https://example.com --ai anthropic --ai-key sk-ant-xxx   # or ANTHROPIC_API_KEY env var
./key_hunter --url https://example.com --ai gemini                          # or GOOGLE_API_KEY env var
```

Key flags: `--url` (required, unless set via `--config`), `--config`, `--output`, `--formats` (`json,csv,html,sarif`, default `json`), `--depth`, `--domains`, `--parallel`, `--delay`, `--random-delay`, `--autosave`, `--ignore-robots`, `--include-ext`, `--proxies`, `--ai`, `--ai-model`, `--ai-key`, `--ai-url` (Ollama base URL), `--ai-workers`, `--min-confidence`.

Recon / secret-hunting flags: `--wayback`, `--otx`, `--otx-key` (enables OTX passive-DNS subdomains), `--crtsh`, `--subdomain-scope` (crawl across discovered subdomains — only widens scope when `--domains` is set), `--active-recon` (gated), `--validate` (gated), `--entropy`, `--entropy-threshold` (bits/char, default `4.0`).

## Architecture

The code is split across a small number of files, each owning one concern (all `package main`, no internal packages):

1. **`api-hunter.go`** — `main()`: flag parsing, config-file/CLI-flag merging, Colly collector construction and event handlers, the seed/validation phase wiring, SIGINT/SIGTERM handling, and the final summary printout. Holds the detection core: `storeFinding` (append + print + non-blocking AI-queue, shared by *every* detector), `markSeen` (dedup by `url:keyType:value`), `checkForKeys`/`checkForKeysWithSource`, `scanEntropy`, `handleSensitivePath`, and the shared helpers (`maskKey`, `maskKeyForAI`, `extractContext`, `isCommonFalsePositive`, `splitCSV`, `matchesExtension`). The global `entropyConfig` is set here and read by `scanEntropy`.
2. **`config.go`** — `Config` (YAML-tagged struct mirroring the CLI flags, with nested `AI`, `Patterns`, `Sources`, and `Entropy` sections plus top-level `active_recon`/`subdomain_scope`/`validate`), `LoadConfig`, and the `resolve*` helpers (`resolveString`/`resolveInt`/`resolveFloat`/`resolveBool`/`resolveStrings`) that implement the flag/config precedence rule (see below).
3. **`patterns.go`** — `APIKeyPattern` type, `defaultPatterns()` (the full list of built-in regexes), `filterPatterns()` (config `patterns.enable`/`patterns.disable` by `Name`), and `looksLikeGitConfig()` (recognizes exposed `.git/config`/`HEAD`/`index` bodies).
4. **`ai.go`** — `AIProvider`, `AIConfig`, `AIClient` and one method per provider (`verifyWithOllama`/`verifyWithOpenAI`/`verifyWithAnthropic`/`verifyWithGemini`), plus shared `buildVerificationPrompt`/`parseAIResponse`. Results cached per `AIClient` by `keyType:keyValue`. Owns `startVerificationWorkers`/`verificationWorker` (goroutines over `verificationQueue`, a buffered `chan *Finding`) and the AI globals (`aiConfig`, `aiClient`, `verificationQueue`, `wg`).
5. **`output.go`** — `Finding` type, the findings globals (`findings`, `findingsMutex`, `seenKeys`, `seenMutex`, `outputFile`, `outputFormats`), `autoSave`, and `SaveResults(formats, baseName)` — the dispatcher writing one file per format (`writeJSON`/`writeCSV`/`writeHTML`/`writeSARIF`) off a shared filename stem.
6. **`recon.go`** — the seed phase. `gatherSeeds(targetURL, ReconOptions) reconResult` orchestrates each source in its own timeout-bounded, graceful-skip function: `fetchRobotsSitemap`, `fetchWaybackURLs`, `fetchOTXURLs` (anonymous), `fetchOTXPassiveDNS` (needs key), `fetchCrtShSubdomains`. Also the sensitive-path wordlist (`sensitivePaths`/`expandSensitivePaths`/`isSensitivePathURL`).
7. **`sourcemap.go`** — `extractSourceMapURLs` (finds `sourceMappingURL` refs + the `.js`→`.js.map` fallback), `looksLikeSourceMap` (routes generically-typed `.map` bodies), and `scanSourceMap` (parses the map, runs detection over each `sourcesContent[]` entry).
8. **`entropy.go`** — `shannonEntropy` and `findHighEntropyTokens` with false-positive guardrails (`looksLikeSecret` requiring ≥2 char classes, `looksLikeFilenameOrURL`, `isCommonFalsePositive`, min length, per-scan cap).
9. **`validate.go`** — `KeyValidator` with per-provider non-destructive checks (OpenAI, GitHub, GitLab, Stripe, Slack, SendGrid), `runValidation` (worker pool over `findings`), and `isSyntheticKeyType` (skips entropy/exposure markers, which have no provider to validate).

### Data flow

**Phase 1 (recon):** `gatherSeeds` (recon.go) returns seed URLs + subdomains; `main` feeds seeds into `c.Visit` and, under `--subdomain-scope`, appends subdomains to `c.AllowedDomains`. **Phase 2 (crawl):** Colly fetches → `OnHTML`/`OnResponse` handlers → `checkForKeys`/`scanEntropy`/`scanSourceMap`/`handleSensitivePath` → each detector builds a `Finding` and calls `storeFinding`, which appends to the global `findings` slice (setting `Source`) and, if AI is enabled, pushes a `*Finding` onto `verificationQueue` for a `verificationWorker` to fill in the `AI*` fields in place. **Phase 3 (validation):** after `c.Wait()` and AI drain, `runValidation` (validate.go) fills `Validated`/`Live`/`ValidationDetail` on each real-key finding. Finally `SaveResults` serializes `findings` to every configured format.

### Config file / CLI flag precedence

Precedence is **default < config file (`--config`) < explicit CLI flag**. `main()` uses `flag.Visit` to record which flag names were actually passed on the command line, then calls the `resolve*` helpers in `config.go` for every setting: an explicitly-passed flag always wins; otherwise a non-zero config file value wins; otherwise the flag's own default is used. This means a config file can supply the whole scan configuration (including `url:`), while any individual CLI flag still overrides just that one value.

### Adding a new secret pattern

Add an entry to the slice returned by `defaultPatterns()` in `patterns.go`: `{Name, regexp.MustCompile(...), Description, Severity}`. If the regex has a capture group, `checkForKeys` uses `match[1]` as the key value instead of the full match (used for context-anchored patterns like `api_key: "..."` where you only want the value, not the surrounding field name — follow this convention for any new pattern whose raw format is too generic to match unanchored, e.g. plain hex/UUID tokens).

### Adding a new AI provider

Add a new `AIProvider` constant, a `verifyWith<Provider>` method on `AIClient` in `ai.go` following the existing request/parse pattern (build provider-specific request body → POST → unmarshal provider-specific response shape → pass the extracted text to `parseAIResponse`), wire it into the `switch` in `VerifyAPIKey`, and add default-model/env-var-key handling in `main()` (`api-hunter.go`).

### Adding a new output format

Add a case to the `switch` in `SaveResults` (`output.go`) and a `write<Format>(filename string, ...)` function alongside `writeJSON`/`writeCSV`/`writeHTML`/`writeSARIF`, then add the format name to `validFormats` in `main()`. Decide deliberately whether the new format should include the raw `Value` field or only `MaskedValue` — see the convention below.

### Adding a new OSINT seed source

Add a timeout-bounded fetch function in `recon.go` returning `([]string, error)` (or `(urls, hosts, error)`), call it from `gatherSeeds` behind a `ReconOptions` toggle, and **always degrade gracefully** — log a warning and continue on any error (OSINT endpoints are flaky; crt.sh and Wayback routinely time out or block). Add the toggle to `ConfigSources` (`config.go`) and a flag in `main()`.

### Adding a new key validator

Add a `check<Provider>` method on `KeyValidator` (`validate.go`) issuing a single documented, **read-only** request (whoami/list/balance — never a mutation) with the found key, returning a `validationOutcome`; wire it into the `dispatch` switch keyed on `KeyType`. Unsupported types must return `Supported:false` with a clear detail, never a false `Live`.

## Conventions / gotchas

- Global mutable state is package-level, not passed as parameters — mutate it under the corresponding mutex (`findingsMutex` for `findings`, `seenMutex` for `seenKeys`) rather than introducing new locking.
- **All detectors funnel through `storeFinding` + `markSeen`** (api-hunter.go). New detection code should build a `Finding` (setting `Source`), call `markSeen(url, keyType, value)` to dedup, then `storeFinding` — do not re-implement the append/print/AI-queue logic.
- `checkForKeysWithSource` filters out matches with `len(keyValue) <= 10` or that match `isCommonFalsePositive` before they become `Finding`s — false-positive suppression happens before dedup/storage, not after.
- Queueing to `verificationQueue` uses a non-blocking `select`/`default` (drops the finding from AI verification, but keeps it in `findings`, if the queue is full) — don't change this to a blocking send without considering crawl throughput.
- **Synthetic vs. real key types**: `High-Entropy String`, `Git Repository Exposure`, and `Exposed Sensitive File` are markers, not provider credentials — `isSyntheticKeyType` (validate.go) excludes them from validation. A *real* key found inside an exposed file (Source `sensitive-path`) is still validated by its own `KeyType`.
- **Raw value vs. masked value across output formats**: JSON keeps the raw `Value` field (useful for remediation/rotation). CSV, HTML, and SARIF are "shareable" report formats and intentionally include only `MaskedValue` — never extend those writers to emit the raw key. HTML/SARIF surface a `LIVE` marker when `Finding.Live` is set.
- `--include-ext` only gates which fetched content gets passed to `checkForKeys` (via `matchesExtension`); it does not restrict crawling/link discovery. Sensitive-path probes **bypass** this filter (the user asked for those paths directly).
- robots.txt is honored by default (`gocolly`'s own default) — `--ignore-robots` is an explicit, off-by-default opt-out for authorized engagements. `--active-recon` and `--validate` are likewise off by default and print an authorization banner; keep any future intrusive feature on the same opt-in-with-warning footing.
- **Testing `--validate` in this sandbox**: outbound HTTPS goes through an agent proxy that injects the session's real GitHub credentials for `api.github.com`, so a *fake* GitHub token there returns HTTP 200 (false "live"). This is an environment artifact, not a code bug — validate the classify logic against a provider the proxy does not auth-inject (OpenAI/SendGrid correctly 401 a fake key).
- Never commit real API keys/secrets into this repo, including in example output files, test fixtures, or commit messages — this is a secret-scanning tool, so sample data must use obviously-fake values (this repo has no `.gitignore` for scan output; avoid committing `key_hunter_*` result files or any `--output` artifacts).
