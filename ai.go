package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// AI CONFIGURATION & TYPES
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

// AIVerificationResult represents the AI's analysis of a potential key
type AIVerificationResult struct {
	IsRealKey      bool    `json:"is_real_key"`
	Confidence     float64 `json:"confidence"`
	Classification string  `json:"classification"`
	Reasoning      string  `json:"reasoning"`
	KeyType        string  `json:"detected_key_type"`
}

// AI-related global state
var (
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
