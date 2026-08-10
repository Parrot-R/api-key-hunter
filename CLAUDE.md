# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

API Hunter is a single-binary Go CLI that crawls a website (via `gocolly`) and scans every visited page/script/response body against a set of regex patterns for leaked API keys and secrets (OpenAI, Anthropic, AWS, GitHub, Stripe, Slack, npm, Docker Hub, and many more). Optionally, each detection is sent to an LLM provider (Ollama, OpenAI, Anthropic, Gemini) for a second-pass classification (`real_key` / `placeholder` / `example` / `documentation` / `false_positive`) to cut down false positives. Results can be written as JSON, CSV, HTML, and/or SARIF, with periodic auto-save and save-on-interrupt (Ctrl+C).

The program is a handful of files in `package main` at the repo root (no subpackages). There is no test suite, no CI config, no Makefile, and no Dockerfile in this repo currently.

## Commands

```bash
# Build
go build -o api_hunter .

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

There are no `_test.go` files, so `go test ./...` currently has nothing to run. If you add tests, `go test ./...` and `go test -run TestName ./...` will work normally since this is a standard `go.mod` module (`module api_hunter`, Go 1.24).

### Running a scan

```bash
# Basic crawl, no AI verification
./api_hunter --url https://example.com

# Restrict crawl to specific domains, increase depth
./api_hunter --url https://example.com --domains example.com,cdn.example.com --depth 5

# Multiple output formats
./api_hunter --url https://example.com --formats json,csv,html,sarif --output report

# Only scan JS/config-like files, add jitter, rotate through proxies
./api_hunter --url https://example.com --include-ext .js,.json,.env --random-delay 2 --proxies http://proxy1:8080,http://proxy2:8080

# Driven entirely by a config file (CLI flags still override individual values)
./api_hunter --config config.yaml

# With AI verification (Ollama, local)
./api_hunter --url https://example.com --ai ollama --ai-model llama3.2

# With AI verification (cloud provider, key via flag or env var)
./api_hunter --url https://example.com --ai openai --ai-key sk-xxx --ai-model gpt-4o-mini
./api_hunter --url https://example.com --ai anthropic --ai-key sk-ant-xxx   # or ANTHROPIC_API_KEY env var
./api_hunter --url https://example.com --ai gemini                          # or GOOGLE_API_KEY env var
```

Key flags: `--url` (required, unless set via `--config`), `--config`, `--output`, `--formats` (`json,csv,html,sarif`, default `json`), `--depth`, `--domains`, `--parallel`, `--delay`, `--random-delay`, `--autosave`, `--ignore-robots`, `--include-ext`, `--proxies`, `--ai`, `--ai-model`, `--ai-key`, `--ai-url` (Ollama base URL), `--ai-workers`, `--min-confidence`.

## Architecture

The code is split across a small number of files, each owning one concern (all `package main`, no internal packages):

1. **`api-hunter.go`** — `main()`: flag parsing, config-file/CLI-flag merging, Colly collector construction and event handlers (crawl depth, domain allowlist, rate limiting, proxy rotation, robots.txt handling, extension scoping), SIGINT/SIGTERM handling, and the final summary printout. Also holds `checkForKeys` (the detection entry point) and the shared helpers: masking (`maskKey` for display, `maskKeyForAI` for the LLM prompt), `extractContext`, `isCommonFalsePositive`, `splitCSV`, and `matchesExtension`.
2. **`config.go`** — `Config` (YAML-tagged struct mirroring the CLI flags, including nested `AI` and `Patterns` sections), `LoadConfig`, and the `resolve*` helpers (`resolveString`/`resolveInt`/`resolveFloat`/`resolveBool`/`resolveStrings`) that implement the flag/config precedence rule (see below).
3. **`patterns.go`** — `APIKeyPattern` type, `defaultPatterns()` (the full list of built-in regexes), and `filterPatterns()` (applies a config file's `patterns.enable`/`patterns.disable` lists by pattern `Name`).
4. **`ai.go`** — `AIProvider`, `AIConfig`, `AIClient` and one method per provider (`verifyWithOllama`, `verifyWithOpenAI`, `verifyWithAnthropic`, `verifyWithGemini`), each building a provider-specific HTTP request, plus a shared `buildVerificationPrompt` and `parseAIResponse` that extracts JSON from the LLM's reply (stripping markdown fences). Results are cached in-memory per `AIClient` keyed by `keyType:keyValue`. Also owns `startVerificationWorkers`/`verificationWorker` (goroutines reading from `verificationQueue`, a buffered channel of `*Finding`) and the AI-related global state (`aiConfig`, `aiClient`, `verificationQueue`, `wg`).
5. **`output.go`** — `Finding` type, the findings-related global state (`findings`, `findingsMutex`, `seenKeys`, `seenMutex`, `outputFile`, `outputFormats`), `autoSave` (ticks on an interval and calls `SaveResults`), and `SaveResults(formats []string, baseName string) error` — the dispatcher that writes one file per requested format (`writeJSON`, `writeCSV`, `writeHTML`, `writeSARIF`), sharing a common filename stem with a per-format extension appended.

### Data flow

`c.Visit(url)` → Colly fetches pages → `OnHTML`/`OnResponse` handlers (gated by `matchesExtension` when `--include-ext` is set) call `checkForKeys` → regex matches become `Finding`s appended to the global `findings` slice → if AI is enabled, a pointer to the new `Finding` is pushed onto `verificationQueue` → a `verificationWorker` calls the configured provider's `verifyWith*` method and fills in the `AI*` fields on that same `Finding` in place → `autoSave` (ticker) and the final `main()` call both invoke `SaveResults`, which serializes the current `findings` slice to one file per configured output format.

### Config file / CLI flag precedence

Precedence is **default < config file (`--config`) < explicit CLI flag**. `main()` uses `flag.Visit` to record which flag names were actually passed on the command line, then calls the `resolve*` helpers in `config.go` for every setting: an explicitly-passed flag always wins; otherwise a non-zero config file value wins; otherwise the flag's own default is used. This means a config file can supply the whole scan configuration (including `url:`), while any individual CLI flag still overrides just that one value.

### Adding a new secret pattern

Add an entry to the slice returned by `defaultPatterns()` in `patterns.go`: `{Name, regexp.MustCompile(...), Description, Severity}`. If the regex has a capture group, `checkForKeys` uses `match[1]` as the key value instead of the full match (used for context-anchored patterns like `api_key: "..."` where you only want the value, not the surrounding field name — follow this convention for any new pattern whose raw format is too generic to match unanchored, e.g. plain hex/UUID tokens).

### Adding a new AI provider

Add a new `AIProvider` constant, a `verifyWith<Provider>` method on `AIClient` in `ai.go` following the existing request/parse pattern (build provider-specific request body → POST → unmarshal provider-specific response shape → pass the extracted text to `parseAIResponse`), wire it into the `switch` in `VerifyAPIKey`, and add default-model/env-var-key handling in `main()` (`api-hunter.go`).

### Adding a new output format

Add a case to the `switch` in `SaveResults` (`output.go`) and a `write<Format>(filename string, ...)` function alongside `writeJSON`/`writeCSV`/`writeHTML`/`writeSARIF`, then add the format name to `validFormats` in `main()`. Decide deliberately whether the new format should include the raw `Value` field or only `MaskedValue` — see the convention below.

## Conventions / gotchas

- Global mutable state is package-level, not passed as parameters — mutate it under the corresponding mutex (`findingsMutex` for `findings`, `seenMutex` for `seenKeys`) rather than introducing new locking.
- `checkForKeys` filters out matches with `len(keyValue) <= 10` or that match `isCommonFalsePositive` before they become `Finding`s — false-positive suppression happens before dedup/storage, not after.
- Queueing to `verificationQueue` uses a non-blocking `select`/`default` (drops the finding from AI verification, but keeps it in `findings`, if the queue is full) — don't change this to a blocking send without considering crawl throughput.
- **Raw value vs. masked value across output formats**: JSON keeps the original behavior of including the raw `Value` field (useful for remediation/rotation tooling). CSV, HTML, and SARIF are treated as more "shareable" report formats and intentionally include only `MaskedValue` — never extend those writers to emit the raw key.
- `--include-ext` only gates which fetched content gets passed to `checkForKeys` (via `matchesExtension`); it does not restrict crawling/link discovery, so HTML pages are still visited and followed even when, say, `--include-ext .js` is set.
- robots.txt is honored by default (this is `gocolly`'s own default, not app-specific logic) — `--ignore-robots` is an explicit, off-by-default opt-out for engagements with clear authorization.
- Never commit real API keys/secrets into this repo, including in example output files, test fixtures, or commit messages — this is a secret-scanning tool, so sample data must use obviously-fake values (this repo has no `.gitignore` for scan output; avoid committing `api_hunter_ai_*` result files or any `--output` artifacts).
