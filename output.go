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
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Key Hunter — Scan Report</title>
<style>
	:root{
		--ink:#070b18; --panel:#0f1730; --panel2:#131d3a; --edge:rgba(255,210,87,.18);
		--gold:#ffd257; --amber:#f2b23a; --arcane:#8fe9ff;
		--text:#cdd8f2; --muted:#8a97b8;
		--crit:#ff5f57; --high:#febc2e; --med:#ffe066; --low:#54e08a;
		--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
		--serif:Georgia,"Times New Roman",serif;
		--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
	}
	*{box-sizing:border-box}
	body{ margin:0; background:var(--ink); color:var(--text); font-family:var(--sans); line-height:1.5;
		background-image:radial-gradient(60% 40% at 50% -5%, rgba(255,205,80,.10), transparent 70%); }
	.wrap{ max-width:1200px; margin:0 auto; padding:32px 24px 56px; }
	header{ display:flex; align-items:center; gap:18px; padding-bottom:20px; border-bottom:1px solid var(--edge); }
	header svg{ width:64px; height:64px; flex:0 0 auto; filter:drop-shadow(0 6px 18px rgba(255,190,60,.25)); }
	.brand h1{ margin:0; font-family:var(--serif); font-size:30px; letter-spacing:.10em; font-weight:700;
		background:linear-gradient(180deg,#fff2c4,var(--gold) 45%,var(--amber)); -webkit-background-clip:text; background-clip:text; color:transparent; }
	.brand .sub{ font-family:var(--serif); font-style:italic; color:var(--muted); font-size:13px; letter-spacing:.02em; }
	.chips{ display:flex; flex-wrap:wrap; gap:12px; margin:22px 0 8px; }
	.chip{ background:linear-gradient(180deg,var(--panel2),var(--panel)); border:1px solid var(--edge); border-radius:12px;
		padding:12px 18px; min-width:120px; }
	.chip .k{ font-family:var(--mono); font-size:11px; letter-spacing:.16em; text-transform:uppercase; color:var(--muted); }
	.chip .v{ font-size:24px; font-weight:700; color:var(--text); font-variant-numeric:tabular-nums; }
	.chip.live .v{ color:var(--crit); }
	.tablecard{ margin-top:18px; border:1px solid var(--edge); border-radius:14px; overflow:hidden; background:var(--panel); }
	.scroll{ overflow-x:auto; }
	table{ border-collapse:collapse; width:100%; font-size:13.5px; }
	th,td{ text-align:left; padding:11px 14px; border-bottom:1px solid rgba(255,255,255,.06); vertical-align:top; }
	thead th{ background:rgba(0,0,0,.35); font-family:var(--mono); font-size:11px; letter-spacing:.12em;
		text-transform:uppercase; color:var(--muted); position:sticky; top:0; }
	tbody tr:hover{ background:rgba(143,233,255,.04); }
	td.url{ max-width:340px; word-break:break-all; color:var(--arcane); }
	code{ font-family:var(--mono); color:var(--gold); }
	.pill{ display:inline-block; font-family:var(--mono); font-size:11px; font-weight:700; letter-spacing:.06em;
		text-transform:uppercase; padding:2px 9px; border-radius:999px; border:1px solid transparent; }
	.pill.critical{ color:var(--crit); border-color:var(--crit); background:rgba(255,95,87,.12); }
	.pill.high{ color:var(--high); border-color:var(--high); background:rgba(254,188,46,.12); }
	.pill.medium{ color:var(--med); border-color:var(--med); background:rgba(255,224,102,.10); }
	.pill.low{ color:var(--low); border-color:var(--low); background:rgba(84,224,138,.12); }
	.src{ font-family:var(--mono); font-size:11px; color:var(--muted); }
	.live{ display:inline-block; font-family:var(--mono); font-weight:700; font-size:11px; letter-spacing:.08em;
		color:#0a0a0a; background:linear-gradient(180deg,#ff8b6b,var(--crit)); padding:2px 9px; border-radius:999px;
		box-shadow:0 0 12px rgba(255,95,87,.5); }
	.vdetail{ color:var(--muted); font-size:12px; }
	.empty{ padding:40px; text-align:center; color:var(--muted); }
	footer{ margin-top:26px; text-align:center; font-family:var(--mono); font-size:11px; letter-spacing:.2em;
		text-transform:uppercase; color:var(--muted); opacity:.7; }
</style>
</head>
<body>
<div class="wrap">
<header>
	<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Key Hunter emblem">
		<defs>
			<linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff2c4"/><stop offset=".4" stop-color="#ffd257"/><stop offset="1" stop-color="#d98a1c"/></linearGradient>
			<radialGradient id="b" cx="50%" cy="38%" r="75%"><stop offset="0" stop-color="#1b2748"/><stop offset="1" stop-color="#070b18"/></radialGradient>
		</defs>
		<circle cx="256" cy="256" r="248" fill="url(#b)"/>
		<circle cx="256" cy="256" r="246" fill="none" stroke="url(#g)" stroke-width="12"/>
		<path d="M256 150 C300 150 322 182 330 232 C344 300 360 356 384 402 L128 402 C152 356 168 300 182 232 C190 182 212 150 256 150 Z" fill="#223257"/>
		<path d="M256 176 C232 176 214 200 214 234 C214 262 232 284 256 284 C280 284 298 262 298 234 C298 200 280 176 256 176 Z" fill="#060912"/>
		<g fill="#8fe9ff"><ellipse cx="242" cy="236" rx="7" ry="9"/><ellipse cx="270" cy="236" rx="7" ry="9"/></g>
		<g transform="rotate(38 352 300)">
			<circle cx="352" cy="214" r="40" fill="none" stroke="url(#g)" stroke-width="16"/>
			<rect x="345" y="252" width="14" height="150" rx="6" fill="url(#g)"/>
			<path d="M359 372 h30 v14 h-30 z" fill="url(#g)"/><path d="M359 348 h20 v12 h-20 z" fill="url(#g)"/>
		</g>
	</svg>
	<div class="brand">
		<h1>KEY HUNTER</h1>
		<div class="sub">Scan Report &middot; Guardian of Secrets · Keeper of Configs</div>
	</div>
</header>

<div class="chips">
	<div class="chip"><div class="k">Scan Time</div><div class="v" style="font-size:15px">{{.ScanTime}}</div></div>
	<div class="chip"><div class="k">Total Findings</div><div class="v">{{.TotalFindings}}</div></div>
	<div class="chip live"><div class="k">Live Keys</div><div class="v">{{.LiveKeys}}</div></div>
	<div class="chip"><div class="k">AI Provider</div><div class="v" style="font-size:15px">{{.AIProvider}}</div></div>
</div>

<div class="tablecard">
<div class="scroll">
<table>
<thead>
<tr><th>Severity</th><th>Key Type</th><th>Source</th><th>URL</th><th>Masked Value</th><th>Found At</th><th>AI Class</th><th>Conf.</th><th>Validation</th></tr>
</thead>
<tbody>
{{range .Findings}}
<tr>
<td><span class="pill {{.Severity}}">{{.Severity}}</span></td>
<td>{{.KeyType}}</td>
<td><span class="src">{{.Source}}</span></td>
<td class="url">{{.URL}}</td>
<td><code>{{.MaskedValue}}</code></td>
<td>{{.FoundAt.Format "2006-01-02 15:04:05"}}</td>
<td>{{.AIClassification}}</td>
<td>{{if .AIVerified}}{{printf "%.0f%%" (mul .AIConfidence 100)}}{{end}}</td>
<td>{{if .Live}}<span class="live">🔥 LIVE</span>{{else if .Validated}}<span class="vdetail">{{.ValidationDetail}}</span>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>
{{if not .Findings}}<div class="empty">No findings — the vault held. 🔐</div>{{end}}
</div>

<footer>🗝️ Key Hunter · Hunt every leaked key · Guard every config · #BuiltWithAI</footer>
</div>
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
