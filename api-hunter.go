package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/extensions"
	"github.com/gocolly/colly/v2/proxy"
)

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func maskKeyForAI(key string) string {
	if len(key) <= 12 {
		return key[:3] + "***" + key[len(key)-3:]
	}
	// Show prefix pattern and length for AI analysis
	return fmt.Sprintf("%s...%s (length: %d)", key[:8], key[len(key)-4:], len(key))
}

func maskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	maskLength := len(key) - 8
	return key[:4] + strings.Repeat("*", maskLength) + key[len(key)-4:]
}

func truncateContext(ctx string, maxLen int) string {
	ctx = strings.TrimSpace(ctx)
	if len(ctx) <= maxLen {
		return ctx
	}
	return ctx[:maxLen] + "..."
}

func extractContext(content, key string, windowSize int) string {
	idx := strings.Index(content, key)
	if idx == -1 {
		return ""
	}

	start := idx - windowSize
	if start < 0 {
		start = 0
	}

	end := idx + len(key) + windowSize
	if end > len(content) {
		end = len(content)
	}

	return strings.TrimSpace(content[start:end])
}

func isCommonFalsePositive(value string) bool {
	lowerVal := strings.ToLower(value)
	falsePositives := []string{
		"example", "sample", "test", "placeholder", "your_api_key",
		"your_api_token", "xxxxx", "yyyyy", "zzzzz", "insert", "replace",
		"<api_key>", "<token>", "dummy", "fake", "demo",
	}

	for _, fp := range falsePositives {
		if strings.Contains(lowerVal, fp) {
			return true
		}
	}
	return false
}

// splitCSV splits a comma-separated flag/config value into a trimmed,
// empty-entry-free slice. Returns nil for an empty string.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// matchesExtension reports whether rawURL's path ends with one of the given
// extensions. An empty extensions list matches everything (today's default
// "scan everything" behavior).
func matchesExtension(rawURL string, extensions []string) bool {
	if len(extensions) == 0 {
		return true
	}
	path := rawURL
	if idx := strings.IndexAny(path, "?#"); idx != -1 {
		path = path[:idx]
	}
	path = strings.ToLower(path)
	for _, ext := range extensions {
		if strings.HasSuffix(path, strings.ToLower(ext)) {
			return true
		}
	}
	return false
}

// ============================================================================
// KEY DETECTION
// ============================================================================

func checkForKeys(url string, content string, patterns []APIKeyPattern) {
	for _, pattern := range patterns {
		matches := pattern.Pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			keyValue := match[0]
			if len(match) > 1 && match[1] != "" {
				keyValue = match[1]
			}

			if len(keyValue) <= 10 || isCommonFalsePositive(keyValue) {
				continue
			}

			// Deduplicate
			seenMutex.Lock()
			keySignature := fmt.Sprintf("%s:%s:%s", url, pattern.Name, keyValue)
			if seenKeys[keySignature] {
				seenMutex.Unlock()
				continue
			}
			seenKeys[keySignature] = true
			seenMutex.Unlock()

			// Extract surrounding context for AI analysis
			context := extractContext(content, keyValue, 200)

			finding := Finding{
				URL:         url,
				KeyType:     pattern.Name,
				Value:       keyValue,
				MaskedValue: maskKey(keyValue),
				Context:     context,
				FoundAt:     time.Now().UTC(),
				Severity:    pattern.Severity,
			}

			findingsMutex.Lock()
			findings = append(findings, finding)
			findingIdx := len(findings) - 1
			findingsMutex.Unlock()

			fmt.Printf("\n🎯 [DETECTED] %s\n", pattern.Name)
			fmt.Printf("   🌐 URL: %s\n", url)
			fmt.Printf("   🔑 Value: %s\n", maskKey(keyValue))

			// Queue for AI verification if enabled
			if aiConfig.Provider != ProviderNone && verificationQueue != nil {
				findingsMutex.Lock()
				findingPtr := &findings[findingIdx]
				findingsMutex.Unlock()

				select {
				case verificationQueue <- findingPtr:
					fmt.Printf("   🤖 Queued for AI verification...\n")
				default:
					fmt.Printf("   ⚠️  AI queue full, skipping verification\n")
				}
			}
		}
	}
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	// Command-line flags
	urlFlag := flag.String("url", "", "Target URL to scan (required unless set in --config)")
	outputFlag := flag.String("output", "", "Output file base name (per-format extension is appended)")
	formatsFlag := flag.String("formats", "json", "Comma-separated output formats: json, csv, html, sarif")
	maxDepthFlag := flag.Int("depth", 3, "Maximum crawl depth")
	allowedDomainsFlag := flag.String("domains", "", "Comma-separated allowed domains")
	parallelismFlag := flag.Int("parallel", 2, "Number of parallel requests")
	delayFlag := flag.Int("delay", 1, "Delay between requests in seconds")
	randomDelayFlag := flag.Int("random-delay", 0, "Extra randomized delay (seconds) added on top of --delay")
	autoSaveIntervalFlag := flag.Int("autosave", 30, "Auto-save interval in seconds")
	ignoreRobotsFlag := flag.Bool("ignore-robots", false, "Ignore robots.txt (only for engagements with explicit authorization)")
	includeExtFlag := flag.String("include-ext", "", "Comma-separated file extensions to scan (e.g. .js,.json,.env) - default scans everything")
	proxiesFlag := flag.String("proxies", "", "Comma-separated proxy URLs to rotate requests through")
	configFlag := flag.String("config", "", "Path to a YAML config file (CLI flags override config file values)")

	// AI Configuration Flags
	aiProviderFlag := flag.String("ai", "none", "AI provider: none, ollama, openai, anthropic, gemini")
	aiModelFlag := flag.String("ai-model", "", "AI model name (e.g., llama3.2, gpt-4o-mini, claude-3-haiku-20240307)")
	aiKeyFlag := flag.String("ai-key", "", "AI API key (or set via environment variable)")
	aiURLFlag := flag.String("ai-url", "http://localhost:11434", "Ollama base URL")
	aiWorkersFlag := flag.Int("ai-workers", 3, "Number of AI verification workers")
	minConfidenceFlag := flag.Float64("min-confidence", 0.7, "Minimum AI confidence to report as real key")

	flag.Parse()

	explicitFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicitFlags[f.Name] = true })

	// Load config file, if given
	cfg := &Config{}
	if *configFlag != "" {
		loaded, err := LoadConfig(*configFlag)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			os.Exit(1)
		}
		cfg = loaded
	}

	// Resolve final settings: default < config file < explicit CLI flag
	finalURL := resolveString(explicitFlags["url"], *urlFlag, cfg.URL)
	finalOutput := resolveString(explicitFlags["output"], *outputFlag, cfg.Output)
	finalFormats := resolveStrings(explicitFlags["formats"], splitCSV(*formatsFlag), cfg.Formats)
	finalDepth := resolveInt(explicitFlags["depth"], *maxDepthFlag, cfg.Depth)
	finalDomains := resolveStrings(explicitFlags["domains"], splitCSV(*allowedDomainsFlag), cfg.Domains)
	finalParallel := resolveInt(explicitFlags["parallel"], *parallelismFlag, cfg.Parallel)
	finalDelay := resolveInt(explicitFlags["delay"], *delayFlag, cfg.Delay)
	finalRandomDelay := resolveInt(explicitFlags["random-delay"], *randomDelayFlag, cfg.RandomDelay)
	finalAutoSave := resolveInt(explicitFlags["autosave"], *autoSaveIntervalFlag, cfg.AutoSave)
	finalIgnoreRobots := resolveBool(explicitFlags["ignore-robots"], *ignoreRobotsFlag, cfg.IgnoreRobots)
	finalIncludeExt := resolveStrings(explicitFlags["include-ext"], splitCSV(*includeExtFlag), cfg.IncludeExt)
	finalProxies := resolveStrings(explicitFlags["proxies"], splitCSV(*proxiesFlag), cfg.Proxies)

	finalAIProvider := resolveString(explicitFlags["ai"], *aiProviderFlag, cfg.AI.Provider)
	finalAIModel := resolveString(explicitFlags["ai-model"], *aiModelFlag, cfg.AI.Model)
	finalAIKey := resolveString(explicitFlags["ai-key"], *aiKeyFlag, cfg.AI.Key)
	finalAIURL := resolveString(explicitFlags["ai-url"], *aiURLFlag, cfg.AI.URL)
	finalAIWorkers := resolveInt(explicitFlags["ai-workers"], *aiWorkersFlag, cfg.AI.Workers)
	finalMinConfidence := resolveFloat(explicitFlags["min-confidence"], *minConfidenceFlag, cfg.AI.MinConfidence)

	// Validate required flags
	if finalURL == "" {
		fmt.Println("❌ Error: --url flag (or `url:` in --config) is required")
		fmt.Println("\n📖 Usage: api_hunter --url https://example.com [options]")
		fmt.Println("\n🤖 AI-Accelerated Options:")
		fmt.Println("  --ai          AI provider: none, ollama, openai, anthropic, gemini")
		fmt.Println("  --ai-model    Model name (e.g., llama3.2, gpt-4o-mini)")
		fmt.Println("  --ai-key      API key for cloud providers")
		fmt.Println("  --ai-url      Ollama base URL (default: http://localhost:11434)")
		fmt.Println("  --ai-workers  Number of verification workers (default: 3)")
		fmt.Println("\n📌 Examples:")
		fmt.Println("  # Local AI with Ollama")
		fmt.Println("  api_hunter --url https://example.com --ai ollama --ai-model llama3.2")
		fmt.Println("")
		fmt.Println("  # Cloud AI with OpenAI")
		fmt.Println("  api_hunter --url https://example.com --ai openai --ai-key sk-xxx --ai-model gpt-4o-mini")
		fmt.Println("")
		fmt.Println("  # Cloud AI with Anthropic Claude")
		fmt.Println("  api_hunter --url https://example.com --ai anthropic --ai-key sk-ant-xxx --ai-model claude-3-haiku-20240307")
		fmt.Println("")
		fmt.Println("  # Driven by a config file")
		fmt.Println("  api_hunter --config config.yaml")
		os.Exit(1)
	}

	validFormats := map[string]bool{"json": true, "csv": true, "html": true, "sarif": true}
	if len(finalFormats) == 0 {
		finalFormats = []string{"json"}
	}
	for _, f := range finalFormats {
		if !validFormats[f] {
			fmt.Printf("❌ Error: unknown output format %q (expected json, csv, html, or sarif)\n", f)
			os.Exit(1)
		}
	}

	// Configure AI
	aiConfig = AIConfig{
		Provider:    AIProvider(finalAIProvider),
		APIKey:      finalAIKey,
		Model:       finalAIModel,
		BaseURL:     finalAIURL,
		MaxTokens:   500,
		Temperature: 0.1,
		Timeout:     30 * time.Second,
	}

	// Set default models if not specified
	if aiConfig.Model == "" {
		switch aiConfig.Provider {
		case ProviderOllama:
			aiConfig.Model = "llama3.2"
		case ProviderOpenAI:
			aiConfig.Model = "gpt-4o-mini"
		case ProviderAnthropic:
			aiConfig.Model = "claude-3-haiku-20240307"
		case ProviderGemini:
			aiConfig.Model = "gemini-1.5-flash"
		}
	}

	// Check for API key in environment if not provided
	if aiConfig.APIKey == "" {
		switch aiConfig.Provider {
		case ProviderOpenAI:
			aiConfig.APIKey = os.Getenv("OPENAI_API_KEY")
		case ProviderAnthropic:
			aiConfig.APIKey = os.Getenv("ANTHROPIC_API_KEY")
		case ProviderGemini:
			aiConfig.APIKey = os.Getenv("GOOGLE_API_KEY")
		}
	}

	// Validate AI configuration
	if aiConfig.Provider != ProviderNone && aiConfig.Provider != ProviderOllama && aiConfig.APIKey == "" {
		fmt.Printf("❌ Error: --ai-key required for %s provider\n", aiConfig.Provider)
		os.Exit(1)
	}

	// Initialize AI client if enabled
	if aiConfig.Provider != ProviderNone {
		aiClient = NewAIClient(aiConfig)
		workers := finalAIWorkers
		if workers <= 0 {
			workers = 3
		}
		startVerificationWorkers(workers)
		fmt.Printf("🤖 AI Verification enabled: %s (model: %s)\n", aiConfig.Provider, aiConfig.Model)
	}

	// Resolve active secret patterns (config file enable/disable list)
	patterns := filterPatterns(defaultPatterns(), cfg.Patterns.Enable, cfg.Patterns.Disable)

	// Initialize Colly collector
	collectorOptions := []colly.CollectorOption{
		colly.MaxDepth(finalDepth),
		colly.Async(true),
	}

	if finalIgnoreRobots {
		collectorOptions = append(collectorOptions, colly.IgnoreRobotsTxt())
		fmt.Println("⚠️  Ignoring robots.txt - ensure you have explicit authorization to crawl this target")
	}

	if len(finalDomains) > 0 {
		collectorOptions = append(collectorOptions, colly.AllowedDomains(finalDomains...))
		fmt.Printf("🔒 Restricting crawl to: %s\n", strings.Join(finalDomains, ", "))
	}

	c := colly.NewCollector(collectorOptions...)
	extensions.RandomUserAgent(c)
	extensions.Referer(c)

	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: finalParallel,
		Delay:       time.Duration(finalDelay) * time.Second,
		RandomDelay: time.Duration(finalRandomDelay) * time.Second,
	})

	if len(finalProxies) > 0 {
		proxySwitcher, err := proxy.RoundRobinProxySwitcher(finalProxies...)
		if err != nil {
			fmt.Printf("❌ Error: invalid --proxies list: %v\n", err)
			os.Exit(1)
		}
		c.SetProxyFunc(proxySwitcher)
		fmt.Printf("🌐 Rotating through %d proxies\n", len(finalProxies))
	}

	c.SetRequestTimeout(30 * time.Second)

	if len(finalIncludeExt) > 0 {
		fmt.Printf("📂 Scanning only: %s\n", strings.Join(finalIncludeExt, ", "))
	}

	// Event handlers
	c.OnRequest(func(r *colly.Request) {
		fmt.Printf("🔍 Visiting: %s\n", r.URL.String())
	})

	c.OnHTML("*", func(e *colly.HTMLElement) {
		if !matchesExtension(e.Request.URL.String(), finalIncludeExt) {
			return
		}
		checkForKeys(e.Request.URL.String(), e.Text, patterns)
		for _, attr := range []string{"data-api-key", "data-token", "data-secret"} {
			if val := e.Attr(attr); val != "" {
				checkForKeys(e.Request.URL.String(), val, patterns)
			}
		}
	})

	c.OnResponse(func(r *colly.Response) {
		if !matchesExtension(r.Request.URL.String(), finalIncludeExt) {
			return
		}
		contentType := r.Headers.Get("Content-Type")
		if strings.Contains(contentType, "javascript") || strings.Contains(contentType, "json") || strings.Contains(contentType, "text") {
			checkForKeys(r.Request.URL.String(), string(r.Body), patterns)
		}
	})

	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		if !strings.HasPrefix(link, "mailto:") && !strings.HasPrefix(link, "tel:") {
			e.Request.Visit(e.Request.AbsoluteURL(link))
		}
	})

	c.OnHTML("script[src]", func(e *colly.HTMLElement) {
		e.Request.Visit(e.Request.AbsoluteURL(e.Attr("src")))
	})

	c.OnError(func(r *colly.Response, err error) {
		log.Printf("❌ Error: %s - %v", r.Request.URL, err)
	})

	// Setup output file
	outputFile = finalOutput
	if outputFile == "" {
		timestamp := time.Now().Format("20060102_150405")
		outputFile = fmt.Sprintf("api_hunter_ai_%s", timestamp)
	}
	outputFormats = finalFormats

	// Signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	if finalAutoSave > 0 {
		go autoSave(time.Duration(finalAutoSave) * time.Second)
	}

	go func() {
		<-sigChan
		fmt.Println("\n\n🛑 Interrupted - saving results...")

		// Close verification queue and wait for workers
		if verificationQueue != nil {
			close(verificationQueue)
			wg.Wait()
		}

		SaveResults(outputFormats, outputFile)
		fmt.Printf("✅ Saved %d findings to %s (%s)\n", len(findings), outputFile, strings.Join(outputFormats, ", "))
		os.Exit(0)
	}()

	// Start scan
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🚀 API HUNTER - AI-Accelerated API Key Scanner")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("🎯 Target: %s\n", finalURL)
	fmt.Printf("📊 Max Depth: %d\n", finalDepth)
	if aiConfig.Provider != ProviderNone {
		fmt.Printf("🤖 AI Provider: %s (model: %s)\n", aiConfig.Provider, aiConfig.Model)
		fmt.Printf("📈 Min Confidence: %.0f%%\n", finalMinConfidence*100)
	}
	fmt.Println("⏹️  Press Ctrl+C to stop and save results")
	fmt.Println(strings.Repeat("=", 60) + "\n")

	if err := c.Visit(finalURL); err != nil {
		log.Fatalf("❌ Failed to start: %v", err)
	}

	c.Wait()

	// Wait for AI verification to complete
	if verificationQueue != nil {
		close(verificationQueue)
		fmt.Println("\n⏳ Waiting for AI verification to complete...")
		wg.Wait()
	}

	// Final summary
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("📊 SCAN COMPLETE - RESULTS SUMMARY")
	fmt.Println(strings.Repeat("=", 60))

	// Count statistics
	var realKeys, placeholders, falsePositives int
	for _, f := range findings {
		if f.AIVerified {
			switch f.AIClassification {
			case "real_key":
				realKeys++
			case "placeholder", "example", "documentation":
				placeholders++
			case "false_positive":
				falsePositives++
			}
		}
	}

	fmt.Printf("\n📈 Statistics:\n")
	fmt.Printf("   Total Detections: %d\n", len(findings))
	if aiConfig.Provider != ProviderNone {
		fmt.Printf("   🔴 Real Keys: %d\n", realKeys)
		fmt.Printf("   🟡 Placeholders/Examples: %d\n", placeholders)
		fmt.Printf("   🟢 False Positives Filtered: %d\n", falsePositives)
	}

	// Print high-confidence findings
	fmt.Println("\n🔑 High-Confidence Findings:")
	for i, f := range findings {
		if !f.AIVerified || (f.AIClassification == "real_key" && f.AIConfidence >= finalMinConfidence) {
			fmt.Printf("\n[%d] 🗝️  %s", i+1, f.KeyType)
			if f.AIVerified {
				fmt.Printf(" (%.0f%% confidence)", f.AIConfidence*100)
			}
			fmt.Printf("\n    🌐 %s\n", f.URL)
			fmt.Printf("    🔑 %s\n", f.MaskedValue)
			if f.AIReasoning != "" {
				fmt.Printf("    🤖 %s\n", f.AIReasoning)
			}
		}
	}

	SaveResults(outputFormats, outputFile)
	fmt.Printf("\n💾 Results saved to: %s (%s)\n", outputFile, strings.Join(outputFormats, ", "))
}
