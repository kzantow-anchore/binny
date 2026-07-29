package credentialserve

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/binny/internal/authserver"
)

// Canned secrets the mock `op` binary returns for each op:// reference. These
// are the plaintext values the credential server should resolve and hand back
// to clients.
const (
	opEnvSecret   = "op-env-secret-value"
	opDockerUser  = "op-docker-username"
	opDockerPass  = "op-docker-password"
	encSecret     = "enc-secret-value"
	literalSecret = "literal-secret-value"
	pushSecret    = "literal-push-secret"

	// credPassword is the password used to encrypt enc:// values and handed to
	// `binny credential serve` over stdin.
	credPassword = "test-credential-password"
)

// op:// references wired into the mock `op` binary and the server config.
const (
	opEnvRef     = "op://vault/env/secret"
	opUserRef    = "op://vault/docker/username"
	opPassRef    = "op://vault/docker/password"
	opMissingRef = "op://vault/missing/none" // intentionally unknown: resolver must skip + warn
)

// harness owns a temp HOME containing the mock resolver commands, a server
// config referencing them, and a running `binny credential serve` process.
// Everything keys off os.UserHomeDir(), so pointing subprocess HOME at the temp
// dir isolates the test from the developer's real ~/.binny.
type harness struct {
	t          *testing.T
	home       string // temp HOME
	binnyDir   string // home/.binny
	opScript   string // mock `op` binary
	toolScript string // mock tool that prints its environment
	configPath string // server config.yaml
	encToken   string // enc://<base64> built against credPassword
	port       int
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	home := t.TempDir()
	binnyDir := filepath.Join(home, ".binny")
	require.NoError(t, os.MkdirAll(binnyDir, 0o700))

	// enc:// values are password-based and independent of the server's ephemeral
	// transport key; build one against credPassword, which is handed to the
	// server over stdin at startup.
	encToken, err := authserver.EncryptPassword(credPassword, []byte(encSecret))
	require.NoError(t, err)

	h := &harness{
		t:        t,
		home:     home,
		binnyDir: binnyDir,
		encToken: encToken,
	}
	h.opScript = h.writeMockOp()
	h.toolScript = h.writePrintEnvTool(filepath.Join(home, "mocktool"))
	h.configPath = h.writeServerConfig()
	return h
}

// writeMockOp writes a fake 1Password CLI: the only external command binny
// shells out to when resolving credentials (`op read <ref>`). It returns a
// canned secret per known ref and exits non-zero for unknown refs so the
// resolver's skip-and-warn path is exercised.
func (h *harness) writeMockOp() string {
	h.t.Helper()
	path := filepath.Join(h.home, "mock-op")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "--version" ]; then echo "2.0.0"; exit 0; fi
if [ "$1" = "read" ]; then
  case "$2" in
    %q) printf '%s' %q ;;
    %q) printf '%s' %q ;;
    %q) printf '%s' %q ;;
    *) echo "unknown ref: $2" >&2; exit 1 ;;
  esac
  exit 0
fi
echo "unsupported op invocation: $*" >&2
exit 1
`,
		opEnvRef, "%s", opEnvSecret,
		opUserRef, "%s", opDockerUser,
		opPassRef, "%s", opDockerPass,
	)
	require.NoError(h.t, os.WriteFile(path, []byte(script), 0o755))
	return path
}

// writePrintEnvTool writes a tool that dumps its environment, so a `binny run`
// of it reveals exactly which credentials binny injected. Used by both the
// host layer and (mounted into the container) the docker layer.
func (h *harness) writePrintEnvTool(path string) string {
	h.t.Helper()
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"1.0.0\"; exit 0; fi\nenv\n"
	require.NoError(h.t, os.WriteFile(path, []byte(script), 0o755))
	return path
}

// writeServerConfig writes a config referencing the mock commands and covering
// every value-ref kind binny supports: op:// (mock op), enc:// (in-process
// RSA), and literal. The mocktool credential patterns also exercise arg
// specificity (base "*" vs the more specific "push ghcr.io/*").
func (h *harness) writeServerConfig() string {
	h.t.Helper()
	path := filepath.Join(h.home, "config.yaml")
	// Keep all binny state (the tool store) inside the temp HOME and disable
	// desktop notifications so the test doesn't pollute the working directory
	// with a .tool dir or fire OS banners while resolving op:// values.
	cfg := fmt.Sprintf(`root: %q
desktop-notifications: false
tools:
  - name: op
    version:
      want: v2.0.0
    method: lookup
    with:
      path: %q
  - name: mocktool
    version:
      want: v1.0.0
    method: lookup
    with:
      path: %q
    credentials:
      "*": basecred
      "push ghcr.io/*": pushcred
credentials:
  basecred:
    env:
      - key: OP_SECRET
        token: %q
      - key: ENC_SECRET
        token: %q
      - key: LIT_SECRET
        token: %q
      - key: OP_MISSING
        token: %q
    docker:
      username: %q
      password: %q
  pushcred:
    env:
      - key: PUSH_SECRET
        token: %q
`,
		filepath.Join(h.home, ".tool"),
		h.opScript,
		h.toolScript,
		opEnvRef,
		h.encToken,
		literalSecret,
		opMissingRef,
		opUserRef,
		opPassRef,
		pushSecret,
	)
	require.NoError(h.t, os.WriteFile(path, []byte(cfg), 0o600))
	return path
}

// env returns a clean environment scoped to the temp HOME. BINNY_* vars from
// the developer's shell are dropped so the test store and key live under the
// temp dir.
func (h *harness) env(extra ...string) []string {
	out := []string{
		"HOME=" + h.home,
		"PATH=" + os.Getenv("PATH"),
		"BINNY_LOG_LEVEL=trace",
	}
	return append(out, extra...)
}

// startServer launches the credential server with the approval gate configured
// to auto-approve every request, so resolution/routing assertions run without a
// GUI prompt. It drives the real gate code path via the test-only prompter hook
// (not the production --auto-approve flag), so the gate remains under test.
func (h *harness) startServer(binny string) {
	h.startServerWithApproval(binny, "allow")
}

// startServerWithApproval launches `binny credential serve` with the test-only
// approval prompter forced to the given mode ("allow" or "deny"), reads the port
// it prints on stdout, and registers cleanup to terminate it. The server runs
// until the test ends.
func (h *harness) startServerWithApproval(binny, approvalMode string) {
	h.t.Helper()

	cmd := exec.Command(binny, "credential", "serve", "-c", h.configPath)
	// BINNY_APPROVAL_TEST_MODE drives the real approval gate deterministically
	// (no GUI dialog) so the harness never actively pops a prompt while still
	// exercising the gate; "deny" lets a test assert the gate blocks resolution.
	cmd.Env = h.env("BINNY_APPROVAL_TEST_MODE=" + approvalMode)
	// The server reads the enc:// password from stdin (stdin is not a TTY here).
	cmd.Stdin = strings.NewReader(credPassword + "\n")

	stdout, err := cmd.StdoutPipe()
	require.NoError(h.t, err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	require.NoError(h.t, cmd.Start())

	h.t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if h.t.Failed() {
			h.t.Logf("credential server stderr:\n%s", stderr.String())
		}
	})

	// stdout contract: a single line containing the bound TCP port.
	portCh := make(chan string, 1)
	go func() {
		r := bufio.NewReader(stdout)
		line, _ := r.ReadString('\n')
		portCh <- strings.TrimSpace(line)
		_, _ = io.Copy(io.Discard, r) // drain so the server never blocks on stdout
	}()

	select {
	case line := <-portCh:
		port, err := strconv.Atoi(line)
		require.NoErrorf(h.t, err, "expected a port on stdout, got %q (stderr: %s)", line, stderr.String())
		h.port = port
	case <-time.After(15 * time.Second):
		h.t.Fatalf("timed out waiting for credential server to print its port (stderr: %s)", stderr.String())
	}

	// confirm the discovery file the clients rely on is present
	require.FileExists(h.t, filepath.Join(h.binnyDir, "port"))
}

// runBinny runs a binny subprocess against the temp HOME and returns combined
// stdout/stderr plus the exit error.
func (h *harness) runBinny(binny string, extraEnv []string, args ...string) (string, string, error) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binny, args...)
	cmd.Env = h.env(extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// --- binny binary builders (cached per test process) ---

var (
	buildMu        sync.Mutex
	hostBinaryPath string
	hostBinaryErr  error
	linuxBinary    string
	linuxBinaryErr error
)

func repoRoot(t testing.TB) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	require.NoError(t, err, "unable to find repo root")
	root, err := filepath.Abs(strings.TrimSpace(string(out)))
	require.NoError(t, err)
	return root
}

// buildHostBinny builds a binny binary for the current OS/arch once per test
// process and returns its path.
func buildHostBinny(t *testing.T) string {
	t.Helper()
	buildMu.Lock()
	defer buildMu.Unlock()
	if hostBinaryPath != "" || hostBinaryErr != nil {
		require.NoError(t, hostBinaryErr)
		return hostBinaryPath
	}
	dir, err := os.MkdirTemp("", "binny-host-build-")
	require.NoError(t, err)
	out := filepath.Join(dir, "binny")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/binny")
	cmd.Dir = repoRoot(t)
	if b, err := cmd.CombinedOutput(); err != nil {
		hostBinaryErr = fmt.Errorf("building host binny: %v\n%s", err, b)
		require.NoError(t, hostBinaryErr)
	}
	hostBinaryPath = out
	return out
}

// buildLinuxBinny builds a static linux/amd64 binny once per test process for
// use inside the docker container.
func buildLinuxBinny(t *testing.T) string {
	t.Helper()
	buildMu.Lock()
	defer buildMu.Unlock()
	if linuxBinary != "" || linuxBinaryErr != nil {
		require.NoError(t, linuxBinaryErr)
		return linuxBinary
	}
	dir, err := os.MkdirTemp("", "binny-linux-build-")
	require.NoError(t, err)
	out := filepath.Join(dir, "binny")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/binny")
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if b, err := cmd.CombinedOutput(); err != nil {
		linuxBinaryErr = fmt.Errorf("building linux binny: %v\n%s", err, b)
		require.NoError(t, linuxBinaryErr)
	}
	linuxBinary = out
	return out
}
