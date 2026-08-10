package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ============================================================================
// CONFIG FILE
// ============================================================================

// Config mirrors the CLI flags for use in a YAML config file passed via
// --config. Every field is optional. Precedence when merging is:
// default < config file < explicit CLI flag (an explicitly-passed flag
// always wins - see the resolve* helpers below and their use in main()).
type Config struct {
	URL          string   `yaml:"url"`
	Output       string   `yaml:"output"`
	Formats      []string `yaml:"formats"`
	Depth        int      `yaml:"depth"`
	Domains      []string `yaml:"domains"`
	Parallel     int      `yaml:"parallel"`
	Delay        int      `yaml:"delay"`
	RandomDelay  int      `yaml:"random_delay"`
	AutoSave     int      `yaml:"autosave"`
	IgnoreRobots bool     `yaml:"ignore_robots"`
	IncludeExt   []string `yaml:"include_ext"`
	Proxies      []string `yaml:"proxies"`

	AI       ConfigAI       `yaml:"ai"`
	Patterns ConfigPatterns `yaml:"patterns"`
}

// ConfigAI mirrors the --ai-* flags.
type ConfigAI struct {
	Provider      string  `yaml:"provider"`
	Model         string  `yaml:"model"`
	Key           string  `yaml:"key"`
	URL           string  `yaml:"url"`
	Workers       int     `yaml:"workers"`
	MinConfidence float64 `yaml:"min_confidence"`
}

// ConfigPatterns selects which built-in patterns (by Name, see patterns.go)
// are active. An empty Enable list means "all patterns", Disable is applied
// after Enable and always wins.
type ConfigPatterns struct {
	Enable  []string `yaml:"enable"`
	Disable []string `yaml:"disable"`
}

// LoadConfig reads and parses a YAML config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	return &cfg, nil
}

// resolve* helpers implement "default < config file < explicit CLI flag":
// explicit is true when the caller passed the flag on the command line
// (via flag.Visit); cfgVal is the config-file value (zero value = unset).

func resolveString(explicit bool, flagVal, cfgVal string) string {
	if explicit || cfgVal == "" {
		return flagVal
	}
	return cfgVal
}

func resolveInt(explicit bool, flagVal, cfgVal int) int {
	if explicit || cfgVal == 0 {
		return flagVal
	}
	return cfgVal
}

func resolveFloat(explicit bool, flagVal, cfgVal float64) float64 {
	if explicit || cfgVal == 0 {
		return flagVal
	}
	return cfgVal
}

func resolveBool(explicit bool, flagVal, cfgVal bool) bool {
	if explicit {
		return flagVal
	}
	return cfgVal
}

func resolveStrings(explicit bool, flagVal, cfgVal []string) []string {
	if explicit || len(cfgVal) == 0 {
		return flagVal
	}
	return cfgVal
}
