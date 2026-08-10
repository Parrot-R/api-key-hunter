package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// FINDINGS STATE
// ============================================================================

// Finding represents a detected API key with AI verification
type Finding struct {
	URL         string    `json:"url"`
	KeyType     string    `json:"key_type"`
	Value       string    `json:"value"`
	MaskedValue string    `json:"masked_value"`
	Context     string    `json:"context"`
	FoundAt     time.Time `json:"found_at"`
	Severity    string    `json:"severity"`

	// Source records how this finding was discovered: "crawl", "sourcemap",
	// "wayback", "otx", "sensitive-path", or "entropy".
	Source string `json:"source"`
	// Entropy is the Shannon entropy of the value, populated only for
	// entropy-based detections (0 otherwise).
	Entropy float64 `json:"entropy,omitempty"`

	// AI Verification Results
	AIVerified       bool    `json:"ai_verified"`
	AIConfidence     float64 `json:"ai_confidence"`     // 0.0 to 1.0
	AIClassification string  `json:"ai_classification"` // "real_key", "placeholder", "example", "false_positive"
	AIReasoning      string  `json:"ai_reasoning"`
	AIProvider       string  `json:"ai_provider"`

	// Live Key Validation Results (populated only when --validate is set)
	Validated        bool   `json:"validated"`         // a validation attempt was made and supported
	Live             bool   `json:"live"`              // the key was confirmed active against its provider
	ValidationDetail string `json:"validation_detail"` // human-readable outcome/reason
}

// Global findings state
var (
	findings      []Finding
	findingsMutex sync.Mutex
	seenKeys      = make(map[string]bool)
	seenMutex     sync.Mutex
	outputFile    string
	outputFormats = []string{"json"}
)

// ============================================================================
// AUTO-SAVE
// ============================================================================

func autoSave(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if outputFile != "" && len(findings) > 0 {
			if err := SaveResults(outputFormats, outputFile); err == nil {
				fmt.Printf("[*] Auto-saved %d findings to %s\n", len(findings), outputFile)
			}
		}
	}
}

// ============================================================================
// RESULT OUTPUT (JSON / CSV / HTML / SARIF)
// ============================================================================

// resultsSummary is the JSON output shape, and is also used to derive the
// AI stats shown in the other report formats.
type resultsSummary struct {
	ScanTime       string    `json:"scan_time"`
	TotalFindings  int       `json:"total_findings"`
	AIVerified     int       `json:"ai_verified_count"`
	HighConfidence int       `json:"high_confidence_count"`
	LiveKeys       int       `json:"live_keys_count"`
	AIProvider     string    `json:"ai_provider"`
	Findings       []Finding `json:"findings"`
}

func buildSummary() resultsSummary {
	results := resultsSummary{
		ScanTime:      time.Now().UTC().Format(time.RFC3339),
		TotalFindings: len(findings),
		AIProvider:    string(aiConfig.Provider),
		Findings:      findings,
	}
	for _, f := range findings {
		if f.AIVerified {
			results.AIVerified++
			if f.AIConfidence >= 0.7 && f.AIClassification == "real_key" {
				results.HighConfidence++
			}
		}
		if f.Live {
			results.LiveKeys++
		}
	}
	return results
}

// SaveResults writes the current findings to one file per requested format.
// Every format shares baseName's stem (its extension, if any, is stripped
// and replaced with the format-specific one).
//
// JSON keeps today's behavior and includes the raw Value field. CSV, HTML,
// and SARIF are treated as shareable report formats and only ever include
// MaskedValue - never the raw secret.
func SaveResults(formats []string, baseName string) error {
	findingsMutex.Lock()
	defer findingsMutex.Unlock()

	summary := buildSummary()
	stem := strings.TrimSuffix(baseName, filepath.Ext(baseName))

	for _, format := range formats {
		var err error
		switch format {
		case "json":
			err = writeJSON(stem+".json", summary)
		case "csv":
			err = writeCSV(stem+".csv", summary.Findings)
		case "html":
			err = writeHTML(stem+".html", summary)
		case "sarif":
			err = writeSARIF(stem+".sarif.json", summary.Findings)
		default:
			err = fmt.Errorf("unknown output format %q", format)
		}
		if err != nil {
			return fmt.Errorf("failed to write %s output: %w", format, err)
		}
	}
	return nil
}

func writeJSON(filename string, summary resultsSummary) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func writeCSV(filename string, findingsList []Finding) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	w := csv.NewWriter(file)
	defer w.Flush()

	header := []string{"url", "key_type", "severity", "source", "masked_value", "found_at", "ai_verified", "ai_confidence", "ai_classification", "ai_reasoning", "validated", "live", "validation_detail"}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, f := range findingsList {
		row := []string{
			f.URL,
			f.KeyType,
			f.Severity,
			f.Source,
			f.MaskedValue,
			f.FoundAt.Format(time.RFC3339),
			fmt.Sprintf("%t", f.AIVerified),
			fmt.Sprintf("%.2f", f.AIConfidence),
			f.AIClassification,
			f.AIReasoning,
			fmt.Sprintf("%t", f.Validated),
			fmt.Sprintf("%t", f.Live),
			f.ValidationDetail,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return w.Error()
}

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>API Hunter Report</title>
<style>
	body { font-family: -apple-system, Arial, sans-serif; margin: 2rem; color: #1a1a1a; }
	h1 { margin-bottom: 0.25rem; }
	.meta { color: #555; margin-bottom: 1.5rem; }
	table { border-collapse: collapse; width: 100%; }
	th, td { border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; font-size: 0.9rem; vertical-align: top; }
	th { background: #f4f4f4; }
	tr.critical { background: #fdeaea; }
	tr.high { background: #fdf3ea; }
	tr.medium { background: #fdfbea; }
	tr.low { background: #f5fdea; }
	code { font-family: ui-monospace, Menlo, monospace; }
	.live { color: #fff; background: #c0281f; font-weight: bold; padding: 0.1rem 0.4rem; border-radius: 3px; }
	.src { color: #555; font-size: 0.8rem; }
</style>
</head>
<body>
<h1>API Hunter Report</h1>
<p class="meta">Scan time: {{.ScanTime}} &middot; Total findings: {{.TotalFindings}} &middot; Live keys: {{.LiveKeys}} &middot; AI provider: {{.AIProvider}}</p>
<table>
<thead>
<tr><th>Severity</th><th>Key Type</th><th>Source</th><th>URL</th><th>Masked Value</th><th>Found At</th><th>AI Classification</th><th>AI Confidence</th><th>Validation</th></tr>
</thead>
<tbody>
{{range .Findings}}
<tr class="{{.Severity}}">
<td>{{.Severity}}</td>
<td>{{.KeyType}}</td>
<td><span class="src">{{.Source}}</span></td>
<td>{{.URL}}</td>
<td><code>{{.MaskedValue}}</code></td>
<td>{{.FoundAt.Format "2006-01-02 15:04:05"}}</td>
<td>{{.AIClassification}}</td>
<td>{{if .AIVerified}}{{printf "%.0f%%" (mul .AIConfidence 100)}}{{end}}</td>
<td>{{if .Live}}<span class="live">LIVE</span>{{else if .Validated}}{{.ValidationDetail}}{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
</body>
</html>
`

var htmlReportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"mul": func(a, b float64) float64 { return a * b },
}).Parse(htmlReportTemplate))

func writeHTML(filename string, summary resultsSummary) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	return htmlReportTmpl.Execute(file, summary)
}

// Minimal SARIF 2.1.0 structures - just enough to represent findings as
// results with a rule per key type, so the report can be ingested by
// generic SARIF tooling.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func writeSARIF(filename string, findingsList []Finding) error {
	seenRules := make(map[string]bool)
	var rules []sarifRule
	var results []sarifResult

	for _, f := range findingsList {
		if !seenRules[f.KeyType] {
			seenRules[f.KeyType] = true
			rules = append(rules, sarifRule{ID: f.KeyType, Name: f.KeyType})
		}

		message := f.AIReasoning
		if message == "" {
			message = fmt.Sprintf("Potential %s detected (masked: %s)", f.KeyType, f.MaskedValue)
		}

		level := sarifLevel(f.Severity)
		if f.Live {
			level = "error"
			message = "VALIDATED LIVE: " + message
		}

		results = append(results, sarifResult{
			RuleID:  f.KeyType,
			Level:   level,
			Message: sarifMessage{Text: message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.URL},
				},
			}},
		})
	}

	logDoc := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "api_hunter", Rules: rules}},
			Results: results,
		}},
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(logDoc)
}

func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
