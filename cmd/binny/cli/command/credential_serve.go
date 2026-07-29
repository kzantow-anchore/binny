package command

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/anchore/binny"
	"github.com/anchore/binny/cmd/binny/cli/option"
	"github.com/anchore/binny/internal/authserver"
	"github.com/anchore/binny/internal/log"
	"github.com/anchore/clio"
	"github.com/anchore/fangs"
)

// appName is the fangs/viper application name (env-var prefix and config-file
// base). It matches the program name used to construct the clio application.
const appName = "binny"

// CredentialServeConfig pulls the credentials map and the tools list from
// ~/.binny/config.yaml. The server needs the tools list so it can match
// incoming commands against tool credential entries; the credentials map
// resolves each cred-ref produced by that match. Core also contributes the
// store root so the resolver can prefer a binny-installed `op` over PATH.
type CredentialServeConfig struct {
	option.Core `json:"" yaml:",inline" mapstructure:",squash"`

	// ConfigFiles is populated by fangs with the set of configuration files
	// actually loaded (in precedence order). The serve loop watches these for
	// changes so it can reload credentials/tools without a restart.
	ConfigFiles []string `json:"config" yaml:"config" mapstructure:"config"`

	// DesktopNotifications controls whether the server fires a desktop
	// notification when a command requires an external (op://) credential
	// lookup. Enabled by default; headless servers and tests set it to false.
	DesktopNotifications bool `json:"desktop-notifications" yaml:"desktop-notifications" mapstructure:"desktop-notifications"`

	// AutoApprove disables the host-side approval gate: when true, any client
	// request resolves credentials without prompting. Off by default; must be
	// explicitly opted into (e.g. for a headless server with no GUI to prompt on).
	AutoApprove bool `json:"auto-approve" yaml:"auto-approve" mapstructure:"auto-approve"`

	// ApprovalTimeout is how long an approved credential stays approved before the
	// next request for it prompts again (parsed as a Go duration; clamped to
	// [1m,10m]). Defaults to 5m.
	ApprovalTimeout string `json:"approval-timeout" yaml:"approval-timeout" mapstructure:"approval-timeout"`
}

// AddFlags registers the serve-specific CLI flags.
func (c *CredentialServeConfig) AddFlags(flags clio.FlagSet) {
	flags.BoolVarP(&c.AutoApprove, "auto-approve", "",
		"resolve credentials without the host approval prompt (opt-in; for headless servers with no GUI)")
	flags.StringVarP(&c.ApprovalTimeout, "approval-timeout", "",
		"how long an approved credential stays approved before re-prompting")
}

func CredentialServe(app clio.Application) *cobra.Command {
	cfg := &CredentialServeConfig{
		Core:                 option.DefaultCore(),
		DesktopNotifications: true,
		ApprovalTimeout:      fmt.Sprintf("%dm", authserver.DefaultApprovalTTL/time.Minute),
	}
	return app.SetupCommand(&cobra.Command{
		Use:   "serve",
		Short: "Run a local credential server so binny clients (e.g. inside a container) can request host credentials",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCredentialServe(cmd.Context(), *cfg)
		},
	}, cfg)
}

// approvalTestModeEnv is a test-only hook: when set to "allow" or "deny" it
// replaces the interactive native prompter with a canned one so the integration
// harness can drive the real approval gate deterministically, with no GUI and
// without disabling the gate via --auto-approve. It is not a supported end-user
// setting.
const approvalTestModeEnv = "BINNY_APPROVAL_TEST_MODE"

// staticPrompter always returns the same approval decision. Used only by the
// test hook above.
type staticPrompter struct{ allow bool }

func (s staticPrompter) Confirm(context.Context, authserver.PromptRequest) (bool, error) {
	return s.allow, nil
}

// serveApprovalPrompter returns the prompter the server should use: a canned
// decision when the test hook is set, otherwise the real native dialog.
func serveApprovalPrompter() authserver.Prompter {
	switch os.Getenv(approvalTestModeEnv) {
	case "allow":
		return staticPrompter{allow: true}
	case "deny":
		return staticPrompter{allow: false}
	default:
		return authserver.NewNativePrompter()
	}
}

func runCredentialServe(ctx context.Context, cfg CredentialServeConfig) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("unable to resolve home directory: %w", err)
	}
	dir := filepath.Join(home, ".binny")

	watcher := newConfigWatcher(cfg)

	approvalTTL, err := time.ParseDuration(cfg.ApprovalTimeout)
	if err != nil {
		return fmt.Errorf("invalid approval-timeout %q: %w", cfg.ApprovalTimeout, err)
	}

	opts := []authserver.Option{
		authserver.WithCommandLookup(option.CredentialMatcher{Tools: cfg.Tools, Credentials: cfg.Credentials}),
		authserver.WithToolResolver(newToolPathFinder(InstallConfig{Core: cfg.Core}, cfg.Tools)),
		authserver.WithReload(watcher.reload),
		authserver.WithNotifications(cfg.DesktopNotifications),
		authserver.WithApproval(approvalTTL, cfg.AutoApprove, serveApprovalPrompter()),
	}

	if cfg.AutoApprove {
		log.Warnf("credential approval gate disabled (--auto-approve): any client request will resolve credentials without host confirmation")
	}

	// enc:// values are decrypted with a user-supplied password; only ask for it
	// when the loaded config actually contains such a value.
	if encValues := encValues(cfg.Credentials); len(encValues) > 0 {
		password, err := acquireServePassword()
		if err != nil {
			return fmt.Errorf("reading credential password: %w", err)
		}
		if password == "" {
			return fmt.Errorf("%d enc:// value(s) configured but no credential password provided", len(encValues))
		}
		// Fail fast on a wrong password rather than at the first resolve request.
		for _, v := range encValues {
			if _, err := authserver.DecryptPassword(password, v); err != nil {
				return fmt.Errorf("credential password does not decrypt configured enc:// values: %w", err)
			}
		}
		opts = append(opts, authserver.WithCredentialPassword(password))
	}

	srv, err := authserver.New(dir, opts...)
	if err != nil {
		return err
	}
	defer func() {
		_ = srv.Close()
	}()

	// stdout contract: a single line containing the bound TCP port.
	_, _ = fmt.Fprintln(os.Stdout, srv.Port())
	log.Infof("credential server listening on port %d", srv.Port())
	if n := len(cfg.Credentials); n > 0 {
		log.Infof("%d credential(s) configured", n)
	} else {
		log.Warnf("no credentials configured in %s/config.yaml", dir)
	}
	if n := len(cfg.Tools); n > 0 {
		log.Infof("%d tool(s) configured", n)
	}
	if n := len(cfg.ConfigFiles); n > 0 {
		log.Infof("watching %d config file(s) for changes: %v", n, cfg.ConfigFiles)
	}

	sigCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return srv.Serve(sigCtx)
}

// encValues collects every value-ref in the credentials map that is an enc://
// (password-encrypted) value, across env bindings and docker login fields.
func encValues(creds option.Credentials) []string {
	var out []string
	add := func(v string) {
		if strings.HasPrefix(v, "enc://") {
			out = append(out, v)
		}
	}
	for _, c := range creds {
		for _, e := range c.Env {
			add(e.Token)
		}
		if c.Docker != nil {
			add(c.Docker.Username)
			add(c.Docker.Password)
		}
	}
	return out
}

// toolResolver resolves a tool name (e.g. "op") to its binny-installed binary
// path by consulting the configured tool list and the on-disk store. When the
// tool is configured but not yet in the store it is installed on demand (the
// same path binny run takes on first use), so a lookup tool configured with an
// explicit path/search-paths is honored without a separate install step.
// Returns "" when the tool isn't configured or cannot be installed, signalling
// the caller to fall back to PATH.
type toolResolver struct {
	cfg   InstallConfig
	tools option.Tools
}

func newToolPathFinder(cfg InstallConfig, tools option.Tools) *toolResolver {
	return &toolResolver{cfg: cfg, tools: tools}
}

func (l *toolResolver) LookupToolPath(name string) string {
	if l == nil {
		return ""
	}
	opt := l.tools.GetOption(name)
	if opt == nil {
		return ""
	}
	store, err := binny.NewStore(l.cfg.Root)
	if err != nil {
		log.WithFields("tool", name, "error", err).Trace("unable to open tool store for path lookup")
		return ""
	}
	entries := store.GetByName(name)
	if len(entries) == 0 {
		// not yet installed: install now so the binary is resolved (honoring a
		// lookup path/search-paths) and recorded, then re-read the store
		if err := installTool(context.Background(), store, l.cfg, *opt); err != nil {
			log.WithFields("tool", name, "error", err).Trace("unable to install tool for path lookup")
			return ""
		}
		entries = store.GetByName(name)
		if len(entries) == 0 {
			return ""
		}
	}
	return entries[0].Path()
}

// configWatcher reloads the credential/tool configuration when any of the
// watched config files changes on disk. The credential server consults it (via
// authserver.WithReload) at the start of each resolve request, so edits to
// ~/.binny/config.yaml (and any other loaded file) take effect without a
// restart.
//
// Reloads re-read the configuration files only: defaults and file contents are
// honored, but CLI-flag/env overrides supplied at startup are not re-applied
// (re-running fangs against the live cobra command would re-bind flags to the
// original config struct, not the freshly loaded one). For the credential
// server the meaningful state — credentials and tools — lives in the config
// files, so this is sufficient.
type configWatcher struct {
	files    []string
	modTimes map[string]fileStamp
}

// fileStamp captures the cheaply-observable identity of a file. Size is tracked
// alongside mtime so a same-second edit that doesn't bump the timestamp is
// still detected.
type fileStamp struct {
	modTime time.Time
	size    int64
}

func newConfigWatcher(cfg CredentialServeConfig) *configWatcher {
	w := &configWatcher{files: cfg.ConfigFiles}
	w.modTimes = stampFiles(cfg.ConfigFiles)
	return w
}

func stampFiles(files []string) map[string]fileStamp {
	stamps := make(map[string]fileStamp, len(files))
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil {
			stamps[f] = fileStamp{modTime: fi.ModTime(), size: fi.Size()}
		}
	}
	return stamps
}

// reload implements authserver.ReloadFunc. It reports a change (and returns a
// rebuilt finder + tool resolver) only when a watched file's stamp differs from
// the last snapshot and the new configuration parses cleanly; a parse error
// during an in-progress edit leaves the previous configuration in place.
func (w *configWatcher) reload() (authserver.CredentialFinder, authserver.ToolResolver, bool) {
	if !w.changed() {
		return nil, nil, false
	}

	fresh, err := loadServeConfig(w.files)
	if err != nil {
		log.WithFields("error", err).Warn("unable to reload credential configuration; keeping previous")
		return nil, nil, false
	}

	// The reloaded config may itself name a different set of files (e.g. a newly
	// added include); track and re-stamp that set going forward.
	w.files = fresh.ConfigFiles
	w.modTimes = stampFiles(w.files)

	matcher := option.CredentialMatcher{Tools: fresh.Tools, Credentials: fresh.Credentials}
	resolver := newToolPathFinder(InstallConfig{Core: fresh.Core}, fresh.Tools)
	return matcher, resolver, true
}

// changed reports whether any watched file's stamp (mtime, size, or existence)
// differs from the last snapshot, updating the snapshot to match.
func (w *configWatcher) changed() bool {
	current := stampFiles(w.files)
	differs := len(current) != len(w.modTimes)
	if !differs {
		for f, cur := range current {
			prev, ok := w.modTimes[f]
			if !ok || prev != cur {
				differs = true
				break
			}
		}
	}
	if differs {
		w.modTimes = current
	}
	return differs
}

// loadServeConfig re-reads the given configuration files into a fresh
// CredentialServeConfig. The baseline must be DefaultCore() (matching the
// initial load) so list-valued config like tools merges by append from an empty
// slice rather than duplicating entries.
func loadServeConfig(files []string) (CredentialServeConfig, error) {
	fresh := CredentialServeConfig{Core: option.DefaultCore()}
	fangsCfg := fangs.NewConfig(appName)
	fangsCfg.Files = files
	if err := fangs.Load(fangsCfg, &cobra.Command{}, &fresh); err != nil {
		return CredentialServeConfig{}, err
	}
	return fresh, nil
}
