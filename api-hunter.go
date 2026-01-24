package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/extensions"
)

// ============================================================================
// CONFIGURATION & TYPES
// ============================================================================

// AIProvider represents supported AI backends
type AIProvider string

const (
	ProviderNone      AIProvider = "none"
	ProviderOllama    AIProvider = "ollama"
	ProviderOpenAI    AIProvider = "openai"
	ProviderAnthropic AIProvider = "anthropic"
	ProviderGemini    AIProvider = "gemini"
)

// AIConfig holds AI provider configuration
type AIConfig struct {
	Provider    AIProvider
	APIKey      string
	Model       string
	BaseURL     string
	MaxTokens   int
	Temperature float64
	Timeout     time.Duration
}

// APIKeyPattern represents a pattern for detecting API keys
type APIKeyPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Description string
	Severity    string // "critical", "high", "medium", "low"
}

// Finding represents a detected API key with AI verification
type Finding struct {
	URL         string    `json:"url"`
	KeyType     string    `json:"key_type"`
	Value       string    `json:"value"`
	MaskedValue string    `json:"masked_value"`
	Context     string    `json:"context"`
	FoundAt     time.Time `json:"found_at"`
	Severity    string    `json:"severity"`

	// AI Verification Results
	AIVerified       bool    `json:"ai_verified"`
	AIConfidence     float64 `json:"ai_confidence"`     // 0.0 to 1.0
	AIClassification string  `json:"ai_classification"` // "real_key", "placeholder", "example", "false_positive"
	AIReasoning      string  `json:"ai_reasoning"`
	AIProvider       string  `json:"ai_provider"`
}

// AIVerificationResult represents the AI's analysis of a potential key
type AIVerificationResult struct {
	IsRealKey      bool    `json:"is_real_key"`
	Confidence     float64 `json:"confidence"`
	Classification string  `json:"classification"`
	Reasoning      string  `json:"reasoning"`
	KeyType        string  `json:"detected_key_type"`
}

// Global state
var (
	findings          []Finding
	findingsMutex     sync.Mutex
	seenKeys          = make(map[string]bool)
	seenMutex         sync.Mutex
	outputFile        string
	aiConfig          AIConfig
	aiClient          *AIClient
	verificationQueue chan *Finding
	wg                sync.WaitGroup
)

// ============================================================================
// AI CLIENT IMPLEMENTATION
// ============================================================================

// AIClient handles communication with AI providers
type AIClient struct {
	config     AIConfig
	httpClient *http.Client
	cache      map[string]*AIVerificationResult
	cacheMutex sync.RWMutex
}

// NewAIClient creates a new AI client
func NewAIClient(config AIConfig) *AIClient {
	return &AIClient{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		cache: make(map[string]*AIVerificationResult),
	}
}

// VerifyAPIKey uses AI to verify if a detected string is a real API key
func (c *AIClient) VerifyAPIKey(ctx context.Context, keyValue, keyType, surrounding string) (*AIVerificationResult, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s", keyType, keyValue)
	c.cacheMutex.RLock()
	if cached, ok := c.cache[cacheKey]; ok {
		c.cacheMutex.RUnlock()
		return cached, nil
	}
	c.cacheMutex.RUnlock()

	// Build the verification prompt
	prompt := c.buildVerificationPrompt(keyValue, keyType, surrounding)

	var result *AIVerificationResult
	var err error

	switch c.config.Provider {
	case ProviderOllama:
		result, err = c.verifyWithOllama(ctx, prompt)
	case ProviderOpenAI:
		result, err = c.verifyWithOpenAI(ctx, prompt)
	case ProviderAnthropic:
		result, err = c.verifyWithAnthropic(ctx, prompt)
	case ProviderGemini:
		result, err = c.verifyWithGemini(ctx, prompt)
	default:
		return &AIVerificationResult{
			IsRealKey:      true,
			Confidence:     0.5,
			Classification: "unverified",
			Reasoning:      "AI verification disabled",
		}, nil
	}

	if err != nil {
		return nil, err
	}

	// Cache the result
	c.cacheMutex.Lock()
	c.cache[cacheKey] = result
	c.cacheMutex.Unlock()

	return result, nil
}

// buildVerificationPrompt creates the prompt for AI verification
func (c *AIClient) buildVerificationPrompt(keyValue, keyType, context string) string {
	// Mask most of the key for security
	maskedKey := maskKeyForAI(keyValue)

	return fmt.Sprintf(`You are a cybersecurity expert specializing in API key and secret detection. Analyze the following potential API key finding and determine if it's a real exposed API key or a false positive.

## Detected Information
- **Detected Key Type**: %s
- **Key Pattern**: %s
- **Surrounding Context**: 
%s

## Analysis Tasks
1. Determine if this is a REAL API key or a FALSE POSITIVE
2. Classify it as one of: "real_key", "placeholder", "example", "documentation", "false_positive"
3. Provide your confidence level (0.0 to 1.0)
4. Explain your reasoning briefly

## Response Format
Respond ONLY with valid JSON in this exact format:
{
  "is_real_key": true/false,
  "confidence": 0.0-1.0,
  "classification": "real_key|placeholder|example|documentation|false_positive",
  "reasoning": "brief explanation",
  "detected_key_type": "service name if identifiable"
}

## Guidelines for Classification
- "real_key": Appears to be an actual, potentially valid API key
- "placeholder": Contains placeholder text like "YOUR_API_KEY", "xxx", "insert-key-here"
- "example": Found in documentation, tutorials, or example code with fake values
- "documentation": Part of API documentation explaining key formats
- "false_positive": Regex matched but clearly not an API key (e.g., random string, hash, UUID used for something else)

Analyze now:`, keyType, maskedKey, truncateContext(context, 500))
}

// verifyWithOllama uses local Ollama for verification
func (c *AIClient) verifyWithOllama(ctx context.Context, prompt string) (*AIVerificationResult, error) {
	reqBody := map[string]interface{}{
		"model":  c.config.Model,
		"prompt": prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": c.config.Temperature,
			"num_predict": c.config.MaxTokens,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", c.config.BaseURL+"/api/generate", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var ollamaResp struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return nil, fmt.Errorf("failed to parse ollama response: %w", err)
	}

	return parseAIResponse(ollamaResp.Response)
}

// verifyWithOpenAI uses OpenAI API for verification
func (c *AIClient) verifyWithOpenAI(ctx context.Context, prompt string) (*AIVerificationResult, error) {
	reqBody := map[string]interface{}{
		"model": c.config.Model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a cybersecurity expert. Respond only with valid JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature": c.config.Temperature,
		"max_tokens":  c.config.MaxTokens,
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var openaiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &openaiResp); err != nil {
		return nil, fmt.Errorf("failed to parse openai response: %w", err)
	}

	if openaiResp.Error != nil {
		return nil, fmt.Errorf("openai error: %s", openaiResp.Error.Message)
	}

	if len(openaiResp.Choices) == 0 {
		return nil, fmt.Errorf("no response from openai")
	}

	return parseAIResponse(openaiResp.Choices[0].Message.Content)
}

// verifyWithAnthropic uses Anthropic Claude API for verification
func (c *AIClient) verifyWithAnthropic(ctx context.Context, prompt string) (*AIVerificationResult, error) {
	reqBody := map[string]interface{}{
		"model":      c.config.Model,
		"max_tokens": c.config.MaxTokens,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.config.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var anthropicResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &anthropicResp); err != nil {
		return nil, fmt.Errorf("failed to parse anthropic response: %w", err)
	}

	if anthropicResp.Error != nil {
		return nil, fmt.Errorf("anthropic error: %s", anthropicResp.Error.Message)
	}

	if len(anthropicResp.Content) == 0 {
		return nil, fmt.Errorf("no response from anthropic")
	}

	return parseAIResponse(anthropicResp.Content[0].Text)
}

// verifyWithGemini uses Google Gemini API for verification
func (c *AIClient) verifyWithGemini(ctx context.Context, prompt string) (*AIVerificationResult, error) {
	reqBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
		"generationConfig": map[string]interface{}{
			"temperature":     c.config.Temperature,
			"maxOutputTokens": c.config.MaxTokens,
		},
	}

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		c.config.Model, c.config.APIKey)

	jsonBody, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gemini request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var geminiResp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &geminiResp); err != nil {
		return nil, fmt.Errorf("failed to parse gemini response: %w", err)
	}

	if geminiResp.Error != nil {
		return nil, fmt.Errorf("gemini error: %s", geminiResp.Error.Message)
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no response from gemini")
	}

	return parseAIResponse(geminiResp.Candidates[0].Content.Parts[0].Text)
}

// parseAIResponse extracts structured data from AI response
func parseAIResponse(response string) (*AIVerificationResult, error) {
	// Extract JSON from response (handle markdown code blocks)
	response = strings.TrimSpace(response)

	// Remove markdown code blocks if present
	if strings.HasPrefix(response, "```json") {
		response = strings.TrimPrefix(response, "```json")
		response = strings.TrimSuffix(response, "```")
	} else if strings.HasPrefix(response, "```") {
		response = strings.TrimPrefix(response, "```")
		response = strings.TrimSuffix(response, "```")
	}
	response = strings.TrimSpace(response)

	// Find JSON object in response
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no valid JSON found in AI response")
	}
	jsonStr := response[start : end+1]

	var result AIVerificationResult
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, fmt.Errorf("failed to parse AI JSON: %w", err)
	}

	// Validate and normalize confidence
	if result.Confidence < 0 {
		result.Confidence = 0
	} else if result.Confidence > 1 {
		result.Confidence = 1
	}

	return &result, nil
}

// ============================================================================
// AI VERIFICATION WORKER
// ============================================================================

// startVerificationWorkers starts background workers for AI verification
func startVerificationWorkers(numWorkers int) {
	verificationQueue = make(chan *Finding, 100)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go verificationWorker(i)
	}
}

// verificationWorker processes findings through AI verification
func verificationWorker(id int) {
	defer wg.Done()

	for finding := range verificationQueue {
		if aiClient == nil || aiConfig.Provider == ProviderNone {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), aiConfig.Timeout)

		result, err := aiClient.VerifyAPIKey(ctx, finding.Value, finding.KeyType, finding.Context)
		cancel()

		findingsMutex.Lock()
		if err != nil {
			log.Printf("[AI Worker %d] Verification failed for %s: %v", id, finding.KeyType, err)
			finding.AIVerified = false
			finding.AIReasoning = fmt.Sprintf("Verification failed: %v", err)
		} else {
			finding.AIVerified = true
			finding.AIConfidence = result.Confidence
			finding.AIClassification = result.Classification
			finding.AIReasoning = result.Reasoning
			finding.AIProvider = string(aiConfig.Provider)

			// Log verification result
			if result.IsRealKey && result.Confidence >= 0.7 {
				fmt.Printf("🤖 [AI VERIFIED] %s (%.0f%% confidence) - %s\n",
					finding.KeyType, result.Confidence*100, result.Classification)
			} else {
				fmt.Printf("🤖 [AI FILTERED] %s classified as %s (%.0f%% confidence)\n",
					finding.KeyType, result.Classification, result.Confidence*100)
			}
		}
		findingsMutex.Unlock()
	}
}

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
// AUTO-SAVE
// ============================================================================

func autoSave(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if outputFile != "" && len(findings) > 0 {
			if err := saveResults(outputFile); err == nil {
				fmt.Printf("[*] Auto-saved %d findings to %s\n", len(findings), outputFile)
			}
		}
	}
}

func saveResults(filename string) error {
	findingsMutex.Lock()
	defer findingsMutex.Unlock()

	// Create results summary
	results := struct {
		ScanTime       string    `json:"scan_time"`
		TotalFindings  int       `json:"total_findings"`
		AIVerified     int       `json:"ai_verified_count"`
		HighConfidence int       `json:"high_confidence_count"`
		AIProvider     string    `json:"ai_provider"`
		Findings       []Finding `json:"findings"`
	}{
		ScanTime:      time.Now().UTC().Format(time.RFC3339),
		TotalFindings: len(findings),
		AIProvider:    string(aiConfig.Provider),
		Findings:      findings,
	}

	// Count AI stats
	for _, f := range findings {
		if f.AIVerified {
			results.AIVerified++
			if f.AIConfidence >= 0.7 && f.AIClassification == "real_key" {
				results.HighConfidence++
			}
		}
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	// Command-line flags
	urlFlag := flag.String("url", "", "Target URL to scan (required)")
	outputFlag := flag.String("output", "", "Output file for results (JSON)")
	maxDepthFlag := flag.Int("depth", 3, "Maximum crawl depth")
	allowedDomainsFlag := flag.String("domains", "", "Comma-separated allowed domains")
	parallelismFlag := flag.Int("parallel", 2, "Number of parallel requests")
	delayFlag := flag.Int("delay", 1, "Delay between requests in seconds")
	autoSaveIntervalFlag := flag.Int("autosave", 30, "Auto-save interval in seconds")

	// AI Configuration Flags
	aiProviderFlag := flag.String("ai", "none", "AI provider: none, ollama, openai, anthropic, gemini")
	aiModelFlag := flag.String("ai-model", "", "AI model name (e.g., llama3.2, gpt-4o-mini, claude-3-haiku-20240307)")
	aiKeyFlag := flag.String("ai-key", "", "AI API key (or set via environment variable)")
	aiURLFlag := flag.String("ai-url", "http://localhost:11434", "Ollama base URL")
	aiWorkersFlag := flag.Int("ai-workers", 3, "Number of AI verification workers")
	minConfidenceFlag := flag.Float64("min-confidence", 0.7, "Minimum AI confidence to report as real key")

	flag.Parse()

	// Validate required flags
	if *urlFlag == "" {
		fmt.Println("❌ Error: --url flag is required")
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
		os.Exit(1)
	}

	// Configure AI
	aiConfig = AIConfig{
		Provider:    AIProvider(*aiProviderFlag),
		APIKey:      *aiKeyFlag,
		Model:       *aiModelFlag,
		BaseURL:     *aiURLFlag,
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
		startVerificationWorkers(*aiWorkersFlag)
		fmt.Printf("🤖 AI Verification enabled: %s (model: %s)\n", aiConfig.Provider, aiConfig.Model)
	}

	// Define API key patterns
	patterns := []APIKeyPattern{
		// AI & Machine Learning APIs
		{"OpenAI API Key (Legacy)", regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}`), "OpenAI legacy format", "critical"},
		{"OpenAI API Key (New)", regexp.MustCompile(`sk-proj-[a-zA-Z0-9-_]{48,}`), "OpenAI project key", "critical"},
		{"Anthropic Claude API Key", regexp.MustCompile(`sk-ant-api03-[a-zA-Z0-9\-_]{95,}`), "Anthropic Claude", "critical"},
		{"Google AI Studio API Key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), "Google AI/Cloud", "critical"},
		{"Hugging Face Token", regexp.MustCompile(`hf_[a-zA-Z0-9]{34,}`), "Hugging Face", "high"},
		{"Replicate API Token", regexp.MustCompile(`r8_[a-zA-Z0-9]{40,}`), "Replicate AI", "high"},
		{"Perplexity AI Key", regexp.MustCompile(`pplx-[a-zA-Z0-9]{32,}`), "Perplexity AI", "high"},

		// Cloud & Infrastructure
		{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS Access Key ID", "critical"},
		{"AWS Secret Key", regexp.MustCompile(`(?i)aws_secret_access_key['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`), "AWS Secret", "critical"},
		{"GitHub PAT", regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), "GitHub Personal Access Token", "critical"},
		{"GitHub Fine-grained Token", regexp.MustCompile(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`), "GitHub Fine-grained PAT", "critical"},
		{"GitLab Token", regexp.MustCompile(`glpat-[a-zA-Z0-9-_]{20,}`), "GitLab Personal Access Token", "critical"},
		{"DigitalOcean Token", regexp.MustCompile(`dop_v1_[a-f0-9]{64}`), "DigitalOcean API Token", "critical"},

		// Payment & Services
		{"Stripe Secret Key", regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24,}`), "Stripe Live Secret Key", "critical"},
		{"Stripe Publishable Key", regexp.MustCompile(`pk_live_[a-zA-Z0-9]{24,}`), "Stripe Live Publishable Key", "medium"},
		{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,48}`), "Slack API Token", "high"},
		{"Discord Token", regexp.MustCompile(`[0-9]{18}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_\-]{27}`), "Discord Bot Token", "high"},
		{"Mailgun API Key", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`), "Mailgun API Key", "high"},
		{"Twilio API Key", regexp.MustCompile(`SK[0-9a-fA-F]{32}`), "Twilio API Key", "high"},
		{"SendGrid API Key", regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`), "SendGrid API Key", "high"},
		{"Shopify API Key", regexp.MustCompile(`shppa_[a-f0-9]{32}`), "Shopify API Key", "high"},

		// Generic Tokens
		{"Generic API Key", regexp.MustCompile(`(?i)api[_-]?key['"]?\s*[:=]\s*['"]?([a-zA-Z0-9\-_]{20,})['"]?`), "Generic API Key pattern", "medium"},
		{"JWT Token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "JSON Web Token", "high"},
		{"Bearer Token", regexp.MustCompile(`(?i)bearer\s+([a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+\.?[a-zA-Z0-9\-_=]*)`), "Bearer Token", "high"},
		{"Private Key Block", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), "Private Key", "critical"},
	}

	// Initialize Colly collector
	collectorOptions := []colly.CollectorOption{
		colly.MaxDepth(*maxDepthFlag),
		colly.Async(true),
	}

	// Determine allowed domains
	var domains []string
	if *allowedDomainsFlag != "" {
		// Use explicitly provided domains
		domains = strings.Split(*allowedDomainsFlag, ",")
		for i := range domains {
			domains[i] = strings.TrimSpace(domains[i])
		}
	} else {
		// Automatically extract domain from target URL
		targetURL, err := url.Parse(*urlFlag)
		if err == nil && targetURL.Host != "" {
			// Extract just the hostname (domain)
			host := targetURL.Host
			// Remove port if present
			if idx := strings.Index(host, ":"); idx != -1 {
				host = host[:idx]
			}
			domains = []string{host}
			fmt.Printf("🔒 Auto-restricting crawl to target domain: %s\n", host)
		}
	}

	if len(domains) > 0 {
		collectorOptions = append(collectorOptions, colly.AllowedDomains(domains...))
		if *allowedDomainsFlag == "" {
			// Already printed above for auto-detection
		} else {
			fmt.Printf("🔒 Restricting crawl to: %s\n", strings.Join(domains, ", "))
		}
	}

	c := colly.NewCollector(collectorOptions...)
	extensions.RandomUserAgent(c)
	extensions.Referer(c)

	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: *parallelismFlag,
		Delay:       time.Duration(*delayFlag) * time.Second,
	})

	c.SetRequestTimeout(30 * time.Second)

	// Event handlers
	c.OnRequest(func(r *colly.Request) {
		fmt.Printf("🔍 Visiting: %s\n", r.URL.String())
	})

	c.OnHTML("*", func(e *colly.HTMLElement) {
		checkForKeys(e.Request.URL.String(), e.Text, patterns)
		for _, attr := range []string{"data-api-key", "data-token", "data-secret"} {
			if val := e.Attr(attr); val != "" {
				checkForKeys(e.Request.URL.String(), val, patterns)
			}
		}
	})

	c.OnResponse(func(r *colly.Response) {
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
	outputFile = *outputFlag
	if outputFile == "" {
		timestamp := time.Now().Format("20060102_150405")
		outputFile = fmt.Sprintf("api_hunter_ai_%s.json", timestamp)
	}

	// Signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	if *autoSaveIntervalFlag > 0 {
		go autoSave(time.Duration(*autoSaveIntervalFlag) * time.Second)
	}

	go func() {
		<-sigChan
		fmt.Println("\n\n🛑 Interrupted - saving results...")

		// Close verification queue and wait for workers
		if verificationQueue != nil {
			close(verificationQueue)
			wg.Wait()
		}

		saveResults(outputFile)
		fmt.Printf("✅ Saved %d findings to %s\n", len(findings), outputFile)
		os.Exit(0)
	}()

	// Start scan
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🚀 API HUNTER - AI-Accelerated API Key Scanner")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("🎯 Target: %s\n", *urlFlag)
	fmt.Printf("📊 Max Depth: %d\n", *maxDepthFlag)
	if aiConfig.Provider != ProviderNone {
		fmt.Printf("🤖 AI Provider: %s (model: %s)\n", aiConfig.Provider, aiConfig.Model)
		fmt.Printf("📈 Min Confidence: %.0f%%\n", *minConfidenceFlag*100)
	}
	fmt.Println("⏹️  Press Ctrl+C to stop and save results")
	fmt.Println(strings.Repeat("=", 60) + "\n")

	if err := c.Visit(*urlFlag); err != nil {
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
		if !f.AIVerified || (f.AIClassification == "real_key" && f.AIConfidence >= *minConfidenceFlag) {
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

	saveResults(outputFile)
	fmt.Printf("\n💾 Results saved to: %s\n", outputFile)
}
