package lookup

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/anchore/binny"
	"github.com/anchore/binny/internal/log"
)

const currentVersion = "current"

// defaultVersionPattern matches a leading 'v' (optional) followed by a dotted numeric version (e.g. 1.2.3 or 1.2)
var defaultVersionPattern = regexp.MustCompile(`v?\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?`)

var _ binny.VersionResolver = (*VersionResolver)(nil)

type VersionResolver struct {
	config     VersionResolutionParameters
	lookupPath func(name string) (string, error)
	runner     func(ctx context.Context, path string, args []string) (string, error)
}

type VersionResolutionParameters struct {
	Name    string   `json:"name" yaml:"name" mapstructure:"name"`
	Args    []string `json:"args" yaml:"args" mapstructure:"args"`
	Pattern string   `json:"pattern" yaml:"pattern" mapstructure:"pattern"`
	// Path is a direct path to the executable; when set, PATH is not searched.
	Path string `json:"path" yaml:"path" mapstructure:"path"`
	// SearchPaths are additional directories searched (in order) ahead of PATH.
	SearchPaths []string `json:"search-paths" yaml:"search-paths" mapstructure:"search-paths"`
}

func NewVersionResolver(cfg VersionResolutionParameters) *VersionResolver {
	return &VersionResolver{
		config: cfg,
		lookupPath: func(name string) (string, error) {
			return findExecutable(name, cfg.Path, cfg.SearchPaths)
		},
		runner: runCommand,
	}
}

func (v VersionResolver) UpdateVersion(ctx context.Context, intent binny.VersionIntent) (string, error) {
	return v.ResolveVersion(ctx, intent)
}

func (v VersionResolver) ResolveVersion(ctx context.Context, intent binny.VersionIntent) (string, error) {
	lgr := log.FromContext(ctx)

	if intent.Cooldown > 0 {
		lgr.WithFields("name", v.config.Name).Warn("cooldown is not supported by the lookup version resolver (ignoring)")
	}

	if v.config.Name == "" && v.config.Path == "" {
		return "", fmt.Errorf("lookup version resolver requires a 'name' or 'path' parameter")
	}

	// honor a user-pinned version unless they explicitly ask for whatever is in PATH
	if intent.Want != "" && intent.Want != currentVersion && intent.Want != "latest" {
		return intent.Want, nil
	}

	sourcePath, err := v.lookupPath(v.config.Name)
	if err != nil {
		return "", fmt.Errorf("failed to find %q in PATH: %w", v.config.Name, err)
	}

	args := v.config.Args
	if len(args) == 0 {
		args = []string{"--version"}
	}

	output, err := v.runner(ctx, sourcePath, args)
	if err != nil {
		return "", fmt.Errorf("failed to run %q to get version: %w", sourcePath, err)
	}

	version, err := extractVersion(output, v.config.Pattern)
	if err != nil {
		return "", err
	}

	lgr.WithFields("name", v.config.Name, "version", version).Trace("resolved version from PATH lookup")

	return version, nil
}

func extractVersion(output, pattern string) (string, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return "", fmt.Errorf("no output from version command")
	}

	re := defaultVersionPattern
	if pattern != "" {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return "", fmt.Errorf("invalid version pattern %q: %w", pattern, err)
		}
	}

	match := re.FindStringSubmatch(output)
	switch len(match) {
	case 0:
		return "", fmt.Errorf("could not extract version from output: %q", output)
	case 1:
		return match[0], nil
	default:
		// when the user supplied a pattern with a capture group, prefer the first capture
		return match[1], nil
	}
}

func runCommand(ctx context.Context, path string, args []string) (string, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}
