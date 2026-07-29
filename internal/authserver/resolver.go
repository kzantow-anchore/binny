package authserver

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/anchore/binny/internal/log"
)

const (
	opPrefix  = "op://"
	encPrefix = "enc://"
)

const (
	// RunOnHost means the credential server executes the command on the host and
	// streams stdout/stderr back; credentials are injected into the server's
	// process and never returned to the client.
	RunOnHost = "host"
)

// ToolResolver returns the installed binary path for a binny-configured tool, or "" to fall back to PATH. Used so the op:// resolver can prefer binny's own `op`.
type ToolResolver interface {
	LookupToolPath(name string) string
}

// CredentialFinder maps a command (tool + args) to unresolved env bindings and docker info; implemented by option.CredentialMatcher.
type CredentialFinder interface {
	GetCredentials(command []string) CommandCredentials
}

// CommandCredentials is the unresolved view. Env is ordered (later wins on key conflict so the most-specific match overrides).
type CommandCredentials struct {
	Name   string
	Env    []EnvBinding
	Docker *DockerRef
	// RunOn is where the command executes: RunOnHost or (any other value) the client.
	RunOn string
}

// EnvBinding pairs an env-var name with its value-ref.
type EnvBinding struct {
	Key   string
	Token string
}

// DockerRef is the unresolved docker login pair; both fields are value-refs.
type DockerRef struct {
	Username string
	Password string
}

// ResolvedCredentials is the plaintext view returned to the client.
type ResolvedCredentials struct {
	Name   string            `json:"name,omitempty"`
	Env    map[string]string `json:"env,omitempty"`
	Docker *UsernameSecret   `json:"docker,omitempty"`
	// RunOn tells the client where to execute the command: RunOnHost means the
	// client should ask the server to run it (env/docker are empty in that case,
	// since the server injects secrets into its own process); any other value
	// means the client runs it locally with the resolved credentials.
	RunOn string `json:"run-on,omitempty"`
}

// UsernameSecret is a resolved username and secret.
type UsernameSecret struct {
	Username string `json:"username,omitempty"`
	Secret   string `json:"secret,omitempty"`
}

// Resolver turns a CommandCredentials (value-refs) into plaintext; password is only needed for enc:// values.
type Resolver struct {
	cmdLookup CredentialFinder
	toolPath  ToolResolver
	password  string
	// notifications controls whether an external (op://) resolve fires a desktop
	// notification. Enabled by default; disabled for headless/test servers.
	notifications bool
	// approvals gates resolution of each value-ref behind a host-side
	// confirmation. Nil means no gate (resolve unconditionally).
	approvals *approvalCache
}

// NewResolver constructs a Resolver; pass password="" when none was supplied (enc:// will then error, op:// and literals still work). Desktop notifications are enabled by default.
func NewResolver(cmdLookup CredentialFinder, password string) *Resolver {
	return &Resolver{cmdLookup: cmdLookup, password: password, notifications: true}
}

// SetApprovals installs the approval gate consulted before each op:///enc://
// resolve; nil disables gating (resolve unconditionally).
func (r *Resolver) SetApprovals(a *approvalCache) {
	if r == nil {
		return
	}
	r.approvals = a
}

// SetToolPathResolver installs a tool-path resolver; nil disables and falls back to PATH.
func (r *Resolver) SetToolPathResolver(l ToolResolver) {
	if r == nil {
		return
	}
	r.toolPath = l
}

// SetNotifications enables or disables desktop notifications for external (op://) resolves.
func (r *Resolver) SetNotifications(enabled bool) {
	if r == nil {
		return
	}
	r.notifications = enabled
}

// ResolveCommand resolves every value-ref for command to plaintext; broken individual refs are logged and skipped.
func (r *Resolver) ResolveCommand(ctx context.Context, command []string) (ResolvedCredentials, error) {
	if r == nil || r.cmdLookup == nil {
		return ResolvedCredentials{}, fmt.Errorf("no command resolver configured")
	}

	cc := r.cmdLookup.GetCredentials(command)

	// When the command runs on the host, the server (not the client) executes it
	// and injects credentials into its own process. Never return secrets to the
	// client, and defer any op:// resolution (and its biometric prompt) until the
	// command actually runs via the exec stream.
	if cc.RunOn == RunOnHost {
		return ResolvedCredentials{Name: cc.Name, RunOn: RunOnHost}, nil
	}

	log.Infof("  ↳ %s", cc.Name)

	out := ResolvedCredentials{
		Name:  cc.Name,
		RunOn: cc.RunOn,
	}
	// silent tracks whether at least one external (op://) ref was resolved
	// without prompting the user. The notification fires only in that case: when
	// the user is shown an approval dialog the dialog is itself the notification,
	// and a denied ref resolves nothing to notify about.
	silent := false
	if len(cc.Env) > 0 {
		out.Env = make(map[string]string, len(cc.Env))
		for _, e := range cc.Env {
			if e.Key == "" {
				continue
			}
			v, silentRef, err := r.resolveValue(ctx, command, cc.Name, e.Token)
			silent = silent || silentRef
			if err != nil {
				log.Warnf("resolve env %q for command=%q failed: %v", e.Key, strings.Join(command, " "), err)
				continue
			}
			out.Env[e.Key] = v
		}
		if len(out.Env) == 0 {
			out.Env = nil
		}
	}

	if cc.Docker != nil {
		var silentDocker bool
		out.Docker, silentDocker = r.resolveDocker(ctx, command, cc.Name, cc.Docker)
		silent = silent || silentDocker
	}

	if r.notifications && silent {
		notifyExternalResolve(command, cc)
	}
	return out, nil
}

func (r *Resolver) resolveDocker(ctx context.Context, command []string, credName string, ref *DockerRef) (*UsernameSecret, bool) {
	out := &UsernameSecret{}
	silent := false
	if ref.Username != "" {
		v, silentRef, err := r.resolveValue(ctx, command, credName, ref.Username)
		silent = silent || silentRef
		if err != nil {
			log.Warnf("resolve docker username for command=%q failed: %v", strings.Join(command, " "), err)
		} else {
			out.Username = v
		}
	}
	if ref.Password != "" {
		v, silentRef, err := r.resolveValue(ctx, command, credName, ref.Password)
		silent = silent || silentRef
		if err != nil {
			log.Warnf("resolve docker password for command=%q failed: %v", strings.Join(command, " "), err)
		} else {
			out.Secret = v
		}
	}
	if out.Username == "" && out.Secret == "" {
		return nil, false
	}
	return out, silent
}

// resolveValue turns a value-ref (op://, enc://, or literal) into plaintext.
// Non-literal refs (op://, enc://) are gated behind the approval cache: a denied
// or un-approvable ref returns an error and is skipped by the caller. Literals
// are returned as-is and never gated (they are already plaintext in config).
//
// The returned bool reports whether an external (op://) ref was resolved
// silently (approved without prompting the user); the caller uses it to decide
// whether to fire a desktop notification. It is never set for enc:// or literal
// refs, which do not notify.
func (r *Resolver) resolveValue(ctx context.Context, command []string, credName, valueRef string) (string, bool, error) {
	switch {
	case strings.HasPrefix(valueRef, opPrefix):
		silent, err := r.authorize(ctx, command, credName, valueRef)
		if err != nil {
			return "", false, err
		}
		// Once authorized silently the credential is being resolved and warrants a
		// notification, even if the op lookup itself subsequently fails.
		v, err := r.resolveOp(ctx, valueRef)
		if err != nil {
			return "", silent, err
		}
		return v, silent, nil
	case strings.HasPrefix(valueRef, encPrefix):
		if _, err := r.authorize(ctx, command, credName, valueRef); err != nil {
			return "", false, err
		}
		v, err := r.resolveEnc(valueRef)
		return v, false, err
	default:
		return valueRef, false, nil
	}
}

// authorize consults the approval gate for a single value-ref, returning an
// error when resolution is not permitted (denied, timed out, or no way to
// prompt). A nil gate permits unconditionally. The returned bool reports whether
// resolution was permitted silently (no dialog shown), as opposed to after the
// user was prompted.
func (r *Resolver) authorize(ctx context.Context, command []string, credName, valueRef string) (bool, error) {
	outcome, err := r.approvals.authorize(ctx, PromptRequest{Command: command, CredentialName: credName, Ref: valueRef})
	if err != nil {
		return false, fmt.Errorf("credential approval prompt failed: %w", err)
	}
	if !outcome.allowed() {
		return false, fmt.Errorf("credential request denied by host approval")
	}
	return outcome == outcomeSilent, nil
}

func (r *Resolver) resolveEnc(valueRef string) (string, error) {
	if r.password == "" {
		return "", fmt.Errorf("cannot decrypt enc:// value: no credential password provided to the server")
	}
	plain, err := DecryptPassword(r.password, valueRef)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (r *Resolver) resolveOp(ctx context.Context, ref string) (string, error) {
	// Prefer a binny-configured `op` over whatever PATH would resolve. This
	// lets a host-side credential server use the 1Password CLI binny manages
	// even when the parent shell's PATH would not find it (e.g. when binny
	// is invoked from a daemon or LaunchAgent context).
	opCmd := "op"
	if r != nil && r.toolPath != nil {
		if p := r.toolPath.LookupToolPath("op"); p != "" {
			opCmd = p
		}
	}
	log.Infof("  ↳ %s", ref)
	cmd := exec.CommandContext(ctx, opCmd, "read", ref)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("op read %s: %s", ref, msg)
	}
	return strings.TrimRight(string(out), "\n"), nil
}
