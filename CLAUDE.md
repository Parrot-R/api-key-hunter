# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

API Hunter is a single-binary Go CLI that crawls a website (via `gocolly`) and scans every visited page/script/response body against a set of regex patterns for leaked API keys and secrets (OpenAI, Anthropic, AWS, GitHub, Stripe, Slack, generic tokens, etc.). Optionally, each detection is sent to an LLM provider (Ollama, OpenAI, Anthropic, Gemini) for a second-pass classification (`real_key` / `placeholder` / `example` / `documentation` / `false_positive`) to cut down false positives. Results are written to a timestamped JSON file, with periodic auto-save and save-on-interrupt (Ctrl+C).

The entire program lives in one file: `api-hunter.go` (~985 lines). There is no test suite, no CI config, no Makefile, and no Dockerfile in this repo currently.

## Commands

```bash
# Build
go build -o api_hunter .

# Run directly without building
go run . --url https://example.com

# Format (the codebase currently has un-gofmt'd sections — run this before committing)
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

# With AI verification (Ollama, local)
./api_hunter --url https://example.com --ai ollama --ai-model llama3.2

# With AI verification (cloud provider, key via flag or env var)
./api_hunter --url https://example.com --ai openai --ai-key sk-xxx --ai-model gpt-4o-mini
./api_hunter --url https://example.com --ai anthropic --ai-key sk-ant-xxx   # or ANTHROPIC_API_KEY env var
./api_hunter --url https://example.com --ai gemini                          # or GOOGLE_API_KEY env var
```

Key flags: `--url` (required), `--output`, `--depth`, `--domains`, `--parallel`, `--delay`, `--autosave`, `--ai`, `--ai-model`, `--ai-key`, `--ai-url` (Ollama base URL), `--ai-workers`, `--min-confidence`.

## Architecture

Everything is in `api-hunter.go`, organized into clearly delimited sections (search for the `// ====...====` banner comments):

1. **Configuration & Types** — `AIProvider`, `AIConfig`, `APIKeyPattern`, `Finding`, `AIVerificationResult`, and package-level global state (`findings`, `seenKeys`, `verificationQueue`, etc., all guarded by mutexes).
2. **AI Client Implementation** (`AIClient`) — one method per provider (`verifyWithOllama`, `verifyWithOpenAI`, `verifyWithAnthropic`, `verifyWithGemini`), each building a provider-specific HTTP request, plus a shared `buildVerificationPrompt` and `parseAIResponse` that extracts JSON from the LLM's reply (stripping markdown fences). Results are cached in-memory per `AIClient` keyed by `keyType:keyValue`.
3. **AI Verification Worker** — `startVerificationWorkers` spins up N goroutines reading from `verificationQueue` (buffered channel of `*Finding`); each worker calls `AIClient.VerifyAPIKey` and mutates the `Finding` in place under `findingsMutex`.
4. **Helper Functions** — masking (`maskKey` for display, `maskKeyForAI` for the LLM prompt), `extractContext` (grabs a window of surrounding text for a match), `isCommonFalsePositive` (substring denylist like "example", "placeholder", "xxxxx").
5. **Key Detection** (`checkForKeys`) — runs every `APIKeyPattern` regex against page content, dedupes via `seenKeys` (keyed by `url:patternName:value`), builds a `Finding`, prints a detection line, and (if AI is enabled) non-blockingly enqueues the finding pointer onto `verificationQueue`.
6. **Auto-Save** — `autoSave` ticks on an interval and calls `saveResults`, which serializes findings + summary stats to the output JSON file.
7. **Main** — flag parsing, AI config resolution (default models per provider, API key fallback to env vars `OPENAI_API_KEY`/`ANTHROPIC_API_KEY`/`GOOGLE_API_KEY`), the `patterns` slice (all regexes for supported secret types — extend this list to add detection for a new key type), Colly collector setup (crawl depth, domain allowlist, rate limiting via `colly.LimitRule`, random user agent), event handlers (`OnHTML("*")` scans page text and `data-api-key`/`data-token`/`data-secret` attributes; `OnResponse` scans JS/JSON/text response bodies; `OnHTML("a[href]")` and `OnHTML("script[src]")` follow links and script sources), SIGINT/SIGTERM handling that drains the verification queue and saves before exit, and the final summary printout.

### Data flow

`c.Visit(url)` → Colly fetches pages → `OnHTML`/`OnResponse` handlers call `checkForKeys` → regex matches become `Finding`s appended to the global `findings` slice → if AI is enabled, a pointer to the new `Finding` is pushed onto `verificationQueue` → a `verificationWorker` calls the configured provider's `verifyWith*` method and fills in the `AI*` fields on that same `Finding` in place → `autoSave` (ticker) and the final `saveResults` call both serialize the current `findings` slice to the output JSON file.

### Adding a new secret pattern

Add an entry to the `patterns` slice in `main()` (`api-hunter.go`, ~line 785): `{Name, regexp.MustCompile(...), Description, Severity}`. If the regex has a capture group, `checkForKeys` uses `match[1]` as the key value instead of the full match (used for patterns like `api_key: "..."` where you only want the value, not the surrounding text).

### Adding a new AI provider

Add a new `AIProvider` constant, a `verifyWith<Provider>` method on `AIClient` following the existing request/parse pattern (build provider-specific request body → POST → unmarshal provider-specific response shape → pass the extracted text to `parseAIResponse`), wire it into the `switch` in `VerifyAPIKey`, and add default-model/env-var-key handling in `main()`.

## Conventions / gotchas

- Global mutable state (`findings`, `seenKeys`, `aiConfig`, `aiClient`, `verificationQueue`) is package-level, not passed as parameters — mutate it under the corresponding mutex (`findingsMutex` / `seenMutex`) rather than introducing new locking.
- `checkForKeys` filters out matches with `len(keyValue) <= 10` or that match `isCommonFalsePositive` before they become `Finding`s — false-positive suppression happens before dedup/storage, not after.
- Queueing to `verificationQueue` uses a non-blocking `select`/`default` (drops the finding from AI verification, but keeps it in `findings`, if the queue is full) — don't change this to a blocking send without considering crawl throughput.
- Never commit real API keys/secrets into this repo, including in example output files, test fixtures, or commit messages — this is a secret-scanning tool, so sample data must use obviously-fake values (this repo has no `.gitignore` for scan output; avoid committing `api_hunter_ai_*.json` result files).
