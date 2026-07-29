package command

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/anchore/binny/cmd/binny/cli/option"
	"github.com/anchore/binny/internal/authserver"
	"github.com/anchore/binny/internal/log"
	"github.com/anchore/binny/internal/redact"
	"github.com/anchore/clio"
)

// resolveCredentials picks how to resolve credentials for command: if a binny
// credential server is reachable (~/.binny/port exists), ask the server so its
// authoritative config wins. Otherwise resolve in-process against cfg.
func resolveCredentials(ctx context.Context, cfg CredentialCheckConfig, command []string) (authserver.ResolvedCredentials, error) {
	if authserver.Available() {
		log.Debugf("contacting credential server for %q", command)
		resolved, err := authserver.ResolveCommand(ctx, command)
		if err != nil {
			return authserver.ResolvedCredentials{}, fmt.Errorf("contacting credential server: %w", err)
		}
		return resolved, nil
	}
	log.Debugf("looking up local credentials for %q", command)
	r := authserver.NewResolver(option.CredentialMatcher{Tools: cfg.Tools, Credentials: cfg.Credentials}, "")
	r.SetToolPathResolver(newToolPathFinder(InstallConfig{Core: cfg.Core}, cfg.Tools))
	resolved, err := r.ResolveCommand(ctx, command)
	if err != nil {
		return authserver.ResolvedCredentials{}, fmt.Errorf("resolving credentials locally: %w", err)
	}
	return resolved, nil
}

type CredentialCheckConfig struct {
	option.Core `json:"" yaml:",inline" mapstructure:",squash"`
}

func CredentialCheck(app clio.Application) *cobra.Command {
	cfg := &CredentialCheckConfig{
		Core: option.DefaultCore(),
	}
	return app.SetupCommand(&cobra.Command{
		Use:   "check TOOL [args...]",
		Short: "Show which credentials would be injected for a given tool invocation",
		Long: `Shows what env vars (and any docker credentials) would be injected
when running TOOL with the given args. If a credential server is reachable
(~/.binny/port exists) the request goes to the server; otherwise credentials
are resolved in-process from the loaded config. Output is redacted; values
are shown only as a fingerprint.`,
		DisableFlagParsing: true,
		Args:               cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCredentialCheck(cmd.Context(), *cfg, args[0], args[1:])
		},
	}, cfg)
}

func runCredentialCheck(ctx context.Context, cfg CredentialCheckConfig, name string, args []string) error {
	// When a credential server is reachable, its config is authoritative — the
	// local config may not list the tool or its credentials at all (e.g. inside
	// a devcontainer that only mounts ~/.binny for discovery). Only enforce the
	// local-config checks when we'll be resolving locally.
	if !authserver.Available() {
		toolCfg := cfg.Tools.GetOption(name)
		if toolCfg == nil {
			return fmt.Errorf("no tool configured with name: %s", name)
		}
		if len(toolCfg.Credentials) == 0 {
			log.Warnf("tool %q has no credentials configured", name)
			return nil
		}
	}

	command := append([]string{name}, args...)
	resolved, err := resolveCredentials(ctx, cfg, command)
	if err != nil {
		return err
	}

	if len(resolved.Env) == 0 && resolved.Docker == nil {
		log.Warnf("no credentials matched %q with args %v", name, args)
		return nil
	}

	keys := make([]string, 0, len(resolved.Env))
	for k := range resolved.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		_, _ = fmt.Fprintf(os.Stdout, "%s=%s\n", k, redact.Preview(resolved.Env[k]))
	}

	if d := resolved.Docker; d != nil {
		switch {
		case d.Username == "" && d.Secret != "":
			_, _ = fmt.Fprintf(os.Stdout, "docker: password=%s\n", redact.Preview(d.Secret))
		case d.Username != "" && d.Secret == "":
			_, _ = fmt.Fprintf(os.Stdout, "docker: username=%s\n", redact.Preview(d.Username))
		default:
			_, _ = fmt.Fprintf(os.Stdout, "docker: username=%s password=%s\n", redact.Preview(d.Username), redact.Preview(d.Secret))
		}
	}
	return nil
}
