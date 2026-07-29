package option

import (
	"fmt"
	"iter"
	"runtime"
	"slices"
	"strings"

	"dario.cat/mergo"
	"github.com/mitchellh/mapstructure"

	"github.com/anchore/binny"
	"github.com/anchore/binny/internal/authserver"
	"github.com/anchore/binny/internal/log"
	"github.com/anchore/binny/internal/redact"
	"github.com/anchore/binny/tool"
	"github.com/anchore/binny/tool/githubrelease"
	"github.com/anchore/binny/tool/gobuild"
	"github.com/anchore/binny/tool/goinstall"
	"github.com/anchore/binny/tool/goproxy"
	"github.com/anchore/binny/tool/hostedshell"
	"github.com/anchore/binny/tool/lookup"
)

type Tool struct {
	Name    string            `json:"name" yaml:"name" mapstructure:"name"`
	Version ToolVersionConfig `json:"version" yaml:"version" mapstructure:"version"`

	InstallMethod string         `json:"method" yaml:"method,omitempty" mapstructure:"method"`
	Parameters    map[string]any `json:"with" yaml:"with,omitempty" mapstructure:"with"`

	// RunOn is where this tool's commands execute: authserver.RunOnHost (the
	// credential server runs the command on the host and streams output back).
	// Any other value (including empty) means the local binny runs it.
	RunOn string `json:"run-on,omitempty" yaml:"run-on,omitempty" mapstructure:"run-on"`

	// Credentials maps an args glob pattern to a credential name from the top-level `credentials:` map. The most-specific match wins per request.
	Credentials map[string]string `json:"credentials,omitempty" yaml:"credentials,omitempty" mapstructure:"credentials"`
}

type ToolVersionConfig struct {
	Want       string `json:"want" yaml:"want" mapstructure:"want"`
	Constraint string `json:"constraint" yaml:"constraint,omitempty" mapstructure:"constraint"`
	// CooldownRaw is the raw config value for the per-tool cooldown duration.
	// Use Cooldown field after PostLoad has been called.
	CooldownRaw   any          `json:"cooldown" yaml:"cooldown,omitempty" mapstructure:"cooldown"`
	Cooldown      JSONDuration `json:"-" yaml:"-" mapstructure:"-"`
	ResolveMethod string       `json:"method" yaml:"method,omitempty" mapstructure:"method"`

	Parameters map[string]any `json:"with" yaml:"with,omitempty" mapstructure:"with"`
}

// PostLoad is called by fangs after config loading to parse raw config values.
func (t *ToolVersionConfig) PostLoad() error {
	if err := t.Cooldown.ParseFrom(t.CooldownRaw); err != nil {
		return fmt.Errorf("invalid cooldown value: %w", err)
	}
	return nil
}

// ToolOptions holds configuration for tool construction behavior.
type ToolOptions struct {
	globalCooldown JSONDuration
	ignoreCooldown bool
}

// DefaultToolOptions returns a ToolOptions with default values.
func DefaultToolOptions() ToolOptions {
	return ToolOptions{}
}

// WithGlobalCooldown sets the global cooldown that applies to all tools (unless overridden per-tool).
func (o ToolOptions) WithGlobalCooldown(d JSONDuration) ToolOptions {
	o.globalCooldown = d
	return o
}

// WithIgnoreCooldown sets whether all cooldowns should be bypassed.
func (o ToolOptions) WithIgnoreCooldown(ignore bool) ToolOptions {
	o.ignoreCooldown = ignore
	return o
}

func (t Tool) ToTool(opts ToolOptions) (binny.Tool, *binny.VersionIntent, error) {
	cfg, intent, err := t.ToConfig(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read tool %q config: %w", t.Name, err)
	}

	toolObj, err := tool.New(*cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to inflate tool %q: %w", cfg.Name, err)
	}
	return toolObj, intent, nil
}

func (t Tool) ToConfig(opts ToolOptions) (*tool.Config, *binny.VersionIntent, error) {
	o := opts

	installParams, err := deriveInstallParameters(t.Name, t.InstallMethod, t.Parameters, runtime.GOOS)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive install parameters for tool %q: %w", t.Name, err)
	}

	versionResolveMethod, versionResolveParams, err := deriveVersionResolveParameters(t.Version.ResolveMethod, t.Version.Parameters)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive version resolution parameters for tool %q: %w", t.Name, err)
	}

	cfg := &tool.Config{
		Name: t.Name,
		InstallerConfig: tool.DetailConfig{
			Method:     t.InstallMethod,
			Parameters: installParams,
		},
		VersionResolverConfig: tool.DetailConfig{
			Method:     versionResolveMethod,
			Parameters: versionResolveParams,
		},
	}

	intent := &binny.VersionIntent{
		Want:       t.Version.Want,
		Constraint: t.Version.Constraint,
		Cooldown:   resolveEffectiveCooldown(o.ignoreCooldown, o.globalCooldown, t.Version.Cooldown),
	}

	return cfg, intent, nil
}

func deriveInstallParameters(name string, installMethod string, installParams map[string]any, goos string) (any, error) {
	switch {
	case goinstall.IsInstallMethod(installMethod):
		var params goinstall.InstallerParameters
		if err := mapstructure.Decode(installParams, &params); err != nil {
			return nil, err
		}
		return params, nil

	case gobuild.IsInstallMethod(installMethod):
		var params gobuild.InstallerParameters
		if err := mapstructure.Decode(installParams, &params); err != nil {
			return nil, err
		}
		return params, nil

	case hostedshell.IsInstallMethod(installMethod):
		var params hostedshell.InstallerParameters
		if err := mapstructure.Decode(installParams, &params); err != nil {
			return nil, err
		}
		return params, nil

	case githubrelease.IsInstallMethod(installMethod):
		var params githubrelease.InstallerParameters
		if err := mapstructure.Decode(installParams, &params); err != nil {
			return nil, err
		}
		if params.Binary == "" {
			// if not provided, assume that the binary name is the same as the configured tool name
			params.Binary = name
			if goos == "windows" {
				params.Binary += ".exe"
			}
		}
		return params, nil
	case lookup.IsInstallMethod(installMethod):
		var params lookup.InstallerParameters
		if err := mapstructure.Decode(installParams, &params); err != nil {
			return nil, err
		}
		if params.Name == "" {
			params.Name = name
		}
		return params, nil
	case installMethod == "":
		return nil, nil
	}
	return nil, fmt.Errorf("unknown install method: %s", installMethod)
}

func deriveVersionResolveParameters(resolveMethod string, versionParameters map[string]any) (string, any, error) {
	switch {
	case githubrelease.IsResolveMethod(resolveMethod):
		var params githubrelease.VersionResolutionParameters
		if err := mapstructure.Decode(versionParameters, &params); err != nil {
			return resolveMethod, nil, err
		}
		return resolveMethod, params, nil

	case goproxy.IsResolveMethod(resolveMethod):
		var params goproxy.VersionResolutionParameters
		if err := mapstructure.Decode(versionParameters, &params); err != nil {
			return resolveMethod, nil, err
		}
		return resolveMethod, params, nil
	case lookup.IsResolveMethod(resolveMethod):
		var params lookup.VersionResolutionParameters
		if err := mapstructure.Decode(versionParameters, &params); err != nil {
			return resolveMethod, nil, err
		}
		return resolveMethod, params, nil
	case resolveMethod == "":
		return resolveMethod, nil, nil
	}

	return resolveMethod, nil, fmt.Errorf("unknown version resolution method: %s", resolveMethod)
}

type Tools []Tool

func (t Tools) GetOption(name string) *Tool {
	// there may be multiple configured tools between local .binny.yaml and ~/.binny.yaml, etc.,
	// these are not merged automatically because this isn't a map, so merge them here
	var out *Tool
	for _, tObj := range t {
		if tObj.Name == name {
			if out != nil {
				err := mergo.Merge(out, tObj)
				if err != nil {
					log.Warnf("failed to merge tool config: %s", err)
				}
			} else {
				out = &tObj
			}
		}
	}
	return out
}

func (t Tools) GetAllOptions(names []string) ([]Tool, error) {
	var notFound []string
	tools := make([]Tool, len(names))
	for i, name := range names {
		tObj := t.GetOption(name)
		if tObj == nil {
			notFound = append(notFound, name)
			continue
		}
		tools[i] = *tObj
	}

	if len(notFound) > 0 {
		return nil, fmt.Errorf("tools not configured: %s", strings.Join(notFound, ", "))
	}

	return tools, nil
}

func (t Tools) Names() []string {
	names := make([]string, len(t))
	for i, tObj := range t {
		names[i] = tObj.Name
	}
	return names
}

// CredentialMatcher pairs Tools with the Credentials map to satisfy authserver.CredentialFinder; tools reference credentials by name.
type CredentialMatcher struct {
	Tools       Tools
	Credentials Credentials
}

// GetCredentials returns the credentials bound to the most-specific pattern that matches command[1:], or empty when no pattern matches.
func (m CredentialMatcher) GetCredentials(command []string) authserver.CommandCredentials {
	if len(command) == 0 {
		return authserver.CommandCredentials{}
	}
	name, args := command[0], command[1:]
	toolCfg := m.Tools.GetOption(name)
	if toolCfg == nil {
		log.Tracef("GetCredentials: tool %q not configured (command=%q)", name, strings.Join(command, " "))
		return authserver.CommandCredentials{}
	}

	// run-on is a tool-level property and applies even when no credential pattern
	// matches (e.g. a host-run command that needs no injected secrets).
	if len(toolCfg.Credentials) == 0 {
		log.Tracef("GetCredentials: no credentials configured for tool %q (command=%q)", name, strings.Join(command, " "))
		return authserver.CommandCredentials{RunOn: toolCfg.RunOn}
	}

	log.Tracef("GetCredentials: matching %d credential entries for tool %q (args=%q)", len(toolCfg.Credentials), name, strings.Join(args, " "))

	for pattern, credName := range bySpecificity(toolCfg.Credentials) {
		if !MatchArgs(pattern, args) {
			log.Tracef("GetCredentials: pattern=%q does NOT match", pattern)
			continue
		}
		log.Tracef("GetCredentials: pattern=%q -> %q matched (specificity=%d)", pattern, credName, argsSpecificity(pattern))

		out := authserver.CommandCredentials{Name: credName, RunOn: toolCfg.RunOn}
		cred, ok := m.Credentials[credName]
		if !ok {
			log.Warnf("tool %q pattern %q references undefined credential %q", name, pattern, credName)
			continue
		}
		for _, e := range cred.Env {
			out.Env = append(out.Env, authserver.EnvBinding{Key: e.Key, Token: e.Token})
			log.Tracef("GetCredentials: pattern=%q env %s -> %s", pattern, e.Key, e.Token)
		}
		if cred.Docker != nil {
			out.Docker = &authserver.DockerRef{
				Username: cred.Docker.Username,
				Password: cred.Docker.Password,
			}
			log.Tracef("GetCredentials: pattern=%q docker username=%s password=%s", pattern, redact.Preview(cred.Docker.Username), redact.Preview(cred.Docker.Password))
		}
		return out
	}

	log.WithFields("command", command).Trace("GetCredentials: no matching credential")
	return authserver.CommandCredentials{RunOn: toolCfg.RunOn}
}

// bySpecificity yields (pattern, credName) entries ordered most- to least-specific so the first match wins.
func bySpecificity(credentials map[string]string) iter.Seq2[string, string] {
	type hit struct {
		pattern  string
		credName string
	}
	var hits []hit
	for pattern, credName := range credentials {
		hits = append(hits, hit{pattern: pattern, credName: credName})
	}
	slices.SortFunc(hits, func(a, b hit) int {
		specificityA, specificityB := argsSpecificity(a.pattern), argsSpecificity(b.pattern)
		if specificityA == specificityB {
			lenA, lenB := len(a.pattern), len(b.pattern)
			if lenA == lenB {
				return -strings.Compare(a.pattern, b.pattern)
			}
			return lenB - lenA
		}
		return specificityB - specificityA
	})
	return func(yield func(string, string) bool) {
		for _, h := range hits {
			if !yield(h.pattern, h.credName) {
				return
			}
		}
	}
}
