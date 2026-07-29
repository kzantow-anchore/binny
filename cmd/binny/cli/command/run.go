package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/scylladb/go-set/strset"
	"github.com/spf13/cobra"

	"github.com/anchore/binny"
	"github.com/anchore/binny/cmd/binny/cli/option"
	"github.com/anchore/binny/internal/authserver"
	"github.com/anchore/binny/internal/log"
	"github.com/anchore/binny/internal/redact"
	"github.com/anchore/binny/tool/lookup"
	"github.com/anchore/clio"
)

// BinnyDockerCredPipeEnv is the env var binny sets when exec'ing a tool that
// needs docker credentials. It holds the path of a per-run named pipe
// (Unix-domain socket) that serves the already-resolved docker username and
// secret as JSON to the docker-credential-binny helper, so the helper never
// has to contact the credential server itself.
//
//nolint:gosec // this is not a credential, it's a pipe finder
const BinnyDockerCredPipeEnv = "BINNY_DOCKER_HELPER_PIPE"

// dockerCredPipeWriteTimeout caps how long the pipe server will wait while
// pushing the credential to a connected client.
const dockerCredPipeWriteTimeout = 5 * time.Second

const (
	// dockerCredSockFileName is the Unix-domain socket the credential pipe
	// listens on, inside the per-run staged docker config dir.
	dockerCredSockFileName = "docker-cred.sock" //nolint:gosec // G101: socket filename, not a credential
	// dockerCredPubKeyFileName is the ephemeral public key published next to the
	// socket; the helper wraps its session key with it. The matching private key
	// lives only in the binny run process memory.
	dockerCredPubKeyFileName = "docker-cred.pub" //nolint:gosec // G101: public-key filename, not a credential
)

type RunConfig struct {
	InstallConfig `json:",inline" mapstructure:",squash"`
}

func Run(app clio.Application) *cobra.Command {
	cfg := &RunConfig{
		InstallConfig: InstallConfig{
			StopOnError: false,
			Core:        option.DefaultCore(),
		},
	}

	var isHelpFlag bool

	return app.SetupCommand(&cobra.Command{
		Use:                "run NAME [command args & flags]",
		Short:              "run a specific tool",
		DisableFlagParsing: true, // pass these as arguments to the tool
		Args:               cobra.ArbitraryArgs,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("no tool name provided")
			}

			name := args[0]

			if name == "--help" || name == "-h" {
				isHelpFlag = true
			}

			// note: this implies that the application configuration needs to be up to date with the tool names
			// installed.
			if !isHelpFlag && !strset.New(cfg.Tools.Names()...).Has(name) {
				return fmt.Errorf("no tool configured with name: %s", name)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var toolArgs []string
			if len(args) > 1 {
				toolArgs = args[1:]
			}

			if isHelpFlag {
				return cmd.Help()
			}

			return runRunRUN(cmd.Context(), *cfg, args[0], toolArgs)
		},
	}, cfg)
}

func runRunRUN(ctx context.Context, cfg RunConfig, name string, args []string) error {
	store, err := binny.NewStore(cfg.Root)
	if err != nil {
		return err
	}

	entries := store.GetByName(name)
	switch len(entries) {
	case 0:
		// install uninstalled tools when first requested
		err = runInstall(ctx, cfg.InstallConfig, []string{name})
		if err != nil {
			// a lookup ("wrapped") tool whose underlying executable can't be
			// located should fail with a concise message rather than the full
			// install/version-resolve error chain.
			if errors.Is(err, lookup.ErrNotFound) {
				return errExecutableNotFound(name)
			}
			return err
		}
		store, err = binny.NewStore(cfg.Root)
		if err != nil {
			return err
		}
		entries = store.GetByName(name)
		if len(entries) != 1 {
			return fmt.Errorf("unable to find tool: %s", name)
		}
	case 1:
		// pass
	default:
		return fmt.Errorf("multiple tools installed with name: %s", name)
	}

	entry := entries[0]

	fullPath, err := filepath.Abs(entry.Path())
	if err != nil {
		return fmt.Errorf("unable to resolve path to tool: %w", err)
	}

	// lookup tools reference a real binary in place (e.g. docker on PATH); that
	// binary may have been removed since it was recorded. Fail cleanly rather
	// than letting exec return a raw "no such file or directory".
	if !isExecutableFile(fullPath) {
		return errExecutableNotFound(name)
	}

	env, cleanup := buildToolEnv(ctx, name, args)
	defer cleanup()

	log.Debugf("running tool %q with env: %s", name, strings.Join(env, ", "))

	c := exec.CommandContext(ctx, fullPath, args...)
	c.Env = env

	if err := runOnPlatform(c); err != nil {
		// the wrapped tool ran but exited non-zero: mirror its exit code verbatim
		// and stay silent (the tool already wrote its own diagnostics). Returning
		// an error here would make clio emit a spurious error line on top of the
		// tool's own output.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			setWrappedExitCode(exitErr.ExitCode())
			return nil
		}
		// the tool could not be launched at all (e.g. removed between the check
		// above and exec): surface it as a not-found so the user learns nothing ran.
		return errExecutableNotFound(name)
	}
	return nil
}

// errExecutableNotFound is the concise error returned when binny is wrapping a
// tool (typically invoked via a symlink such as `docker`) but the underlying
// executable cannot be located. It surfaces as a non-zero exit with a message
// like "executable not found: docker".
func errExecutableNotFound(name string) error {
	return fmt.Errorf("executable not found: %s", name)
}

// isExecutableFile reports whether path exists, is a regular file, and (on
// non-Windows platforms) has an execute bit set.
func isExecutableFile(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	if runtime.GOOS != "windows" && fi.Mode()&0o111 == 0 {
		return false
	}
	return true
}

// buildToolEnv resolves credentials from the credential server if it's running
func buildToolEnv(ctx context.Context, name string, args []string) (env []string, cleanup func()) {
	command := append([]string{name}, args...)

	cleanup = func() {}
	// Prefer the credential server if the port file is present
	if !authserver.Available() {
		log.Debugf("authserver not available for credentials executing: %s", strings.Join(command, " "))
		return nil, cleanup
	}

	resolved, err := authserver.ResolveCommand(ctx, command)
	if err != nil {
		log.Warnf("credential server resolve for tool %q failed: %v", name, err)
		return os.Environ(), cleanup
	}

	envOut := map[string]string{}
	envKeys := make([]string, 0, len(resolved.Env))
	for k, v := range resolved.Env {
		envOut[k] = v
		envKeys = append(envKeys, k)
		if v != "" {
			redact.Add(v)
		}
	}
	if len(envKeys) > 0 {
		sort.Strings(envKeys)
		for _, k := range envKeys {
			log.Debugf("applying credential for tool %q: %s=%s", name, k, redact.Preview(envOut[k]))
		}
	} else {
		log.Debugf("no env credentials resolved for tool %q", name)
	}

	var cleanups []func()

	// Peek at the resolved view only to confirm a docker credential came back
	if resolved.Docker != nil {
		log.Debugf("applying docker credential for tool %q: username=%s secret=%s",
			name, redact.Preview(resolved.Docker.Username), redact.Preview(resolved.Docker.Secret))
		dir, err := stageDockerConfig()
		if err != nil {
			log.Warnf("staging docker config for tool %q: %v", name, err)
		} else {
			cleanups = append(cleanups, func() { _ = os.RemoveAll(dir) })
			envOut["DOCKER_CONFIG"] = dir
			// docker discovers `docker-credential-binny` by name on PATH; the
			// staged dir holds a symlink to the running binny binary so docker
			// can dispatch into the helper subcommand without requiring binny
			// to have been pre-installed on PATH inside the tool's environment.
			envOut["PATH"] = prependPath(os.Getenv("PATH"), dir)

			pipePath, stopPipe, err := startDockerCredPipe(dir, resolved.Docker)
			if err != nil {
				log.Warnf("starting docker credential pipe for tool %q: %v", name, err)
			} else {
				log.Tracef("started docker credential pipe for tool %q at %s", name, pipePath)
				cleanups = append(cleanups, stopPipe)
				envOut[BinnyDockerCredPipeEnv] = pipePath
			}
		}
	}

	if len(cleanups) > 0 {
		cleanup = func() {
			for _, cleaner := range cleanups {
				cleaner()
			}
		}
	}

	env = os.Environ()
	for k, v := range envOut {
		env = append(env, k+"="+v)
	}
	return env, cleanup
}

// stageDockerConfig writes a temporary docker config.json that delegates all
// credential lookups to docker-credential-binny, plus a symlink in the same
// directory pointing the helper name at the currently running binny binary.
func stageDockerConfig() (string, error) {
	dir, err := os.MkdirTemp("", "binny-docker-")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}
	cfg := map[string]any{"credsStore": "binny"}
	body, err := json.Marshal(cfg)
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("encoding docker config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), body, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("writing docker config: %w", err)
	}
	if err := stageDockerCredHelper(dir); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// stageDockerCredHelper writes a `docker-credential-binny` wrapper in dir that invokes the currently running binny binary
func stageDockerCredHelper(dir string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving binny executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return fmt.Errorf("resolving binny executable path: %w", err)
	}

	name, body := dockerCredHelperWrapper(exe)
	helperPath := filepath.Join(dir, name)
	//nolint:gosec // this needs to be executable and writable, it will be deleted after execution
	if err := os.WriteFile(helperPath, []byte(body), 0o700); err != nil {
		return fmt.Errorf("writing docker credential helper wrapper: %w", err)
	}
	return nil
}

// dockerCredHelperWrapper returns the filename and content for the platform's wrapper script
func dockerCredHelperWrapper(binnyExe string) (name, body string) {
	if runtime.GOOS == "windows" {
		return DockerCredentialHelperName + ".cmd",
			"@echo off\r\n\"" + binnyExe + "\" credential " + DockerHelperUse + " %*\r\n"
	}
	// POSIX shell: single-quote the path and replace any embedded ' with the
	// standard '\'' escape so a path containing quotes can't break out.
	escaped := strings.ReplaceAll(binnyExe, "'", `'\''`)
	return DockerCredentialHelperName,
		"#!/bin/sh\nexec '" + escaped + "' credential " + DockerHelperUse + " \"$@\"\n"
}

// prependPath returns existing with dir added as the first PATH entry if not already present
func prependPath(existing, dir string) string {
	if dir == "" {
		return existing
	}
	sep := string(os.PathListSeparator)
	if existing == "" {
		return dir
	}
	for _, p := range strings.Split(existing, sep) {
		if p == dir {
			return existing
		}
	}
	return dir + sep + existing
}

// startDockerCredPipe creates a Unix-domain-socket "named pipe" inside dir and
// spawns a goroutine that hands the resolved docker credential to every client
// that connects. docker-credential-binny is the only intended client; it dials
// the path in BINNY_DOCKER_HELPER_PIPE.
//
// The credential never crosses the socket in plaintext. binny run mints an
// ephemeral RSA key pair, publishes the public half next to the socket
// (docker-cred.pub) and keeps the private half in memory. The helper reads the
// public key, wraps a fresh AES session key with it (SealEnvelope) and sends
// that as a handshake; binny run unwraps it with the private key (OpenEnvelope)
// and returns the credential sealed under that session key (SealResponse). This
// mirrors the client↔credential-server handshake with binny run playing the
// server role. The socket is still chmod 0600 (owner-only); the encryption is
// defense in depth, and the private key dies with the pipe. The returned stop
// func closes the listener (which terminates the goroutine).
func startDockerCredPipe(dir string, cred *authserver.UsernameSecret) (string, func(), error) {
	//nolint:gosec // G117: these bytes are immediately sealed under a per-connection session key (SealResponse) and never leave the process in plaintext
	payload, err := json.Marshal(cred)
	if err != nil {
		return "", nil, fmt.Errorf("encoding docker credential: %w", err)
	}
	if cred.Secret != "" {
		redact.Add(cred.Secret)
	}

	privKey, err := authserver.GenerateKey()
	if err != nil {
		return "", nil, fmt.Errorf("generating docker credential pipe key: %w", err)
	}
	pubKey, err := authserver.PublicKeyFromPrivate(privKey)
	if err != nil {
		return "", nil, fmt.Errorf("deriving docker credential pipe public key: %w", err)
	}
	if err := authserver.SavePublicKey(filepath.Join(dir, dockerCredPubKeyFileName), pubKey); err != nil {
		return "", nil, fmt.Errorf("publishing docker credential pipe public key: %w", err)
	}

	path := filepath.Join(dir, dockerCredSockFileName)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return "", nil, fmt.Errorf("creating credential pipe: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return "", nil, fmt.Errorf("securing credential pipe: %w", err)
	}

	go serveDockerCredPipe(listener, privKey, payload)
	return path, func() { _ = listener.Close() }, nil
}

// serveDockerCredPipe answers each connection with payload (the plaintext
// credential JSON) sealed under the session key the client wraps with the
// pipe's public key. privKey unwraps that handshake.
func serveDockerCredPipe(l net.Listener, privKey string, payload []byte) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return // listener closed during cleanup
		}
		go serveDockerCredConn(conn, privKey, payload)
	}
}

func serveDockerCredConn(c net.Conn, privKey string, payload []byte) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(dockerCredPipeWriteTimeout))

	// the client writes its handshake envelope then half-closes, so read to EOF
	raw, err := io.ReadAll(io.LimitReader(c, 1<<16))
	if err != nil {
		log.Tracef("reading docker credential handshake: %v", err)
		return
	}
	var env authserver.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		log.Tracef("decoding docker credential handshake: %v", err)
		return
	}
	_, sessionKey, err := authserver.OpenEnvelope(privKey, env)
	if err != nil {
		log.Tracef("opening docker credential handshake: %v", err)
		return
	}
	sealed, err := authserver.SealResponse(sessionKey, payload)
	if err != nil {
		log.Tracef("sealing docker credential: %v", err)
		return
	}
	respBytes, err := json.Marshal(sealed)
	if err != nil {
		log.Tracef("encoding docker credential response: %v", err)
		return
	}
	_, _ = c.Write(respBytes)
}
