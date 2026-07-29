package authserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/anchore/binny/internal/log"
)

const (
	portFileName = "port"
	bindAddr     = "127.0.0.1:0"
)

type resolveRequest struct {
	Command []string `json:"command"`
}

// Server listens for credential-resolution requests from binny clients over a
// loopback TCP port. Clients send an RSA-wrapped AES-GCM Envelope containing a
// {command} JSON payload; the server matches command (tool + args) against the
// configured tool credentials, resolves every value-ref (op://, enc://, or
// literal) into plaintext, and returns the full ResolvedCredentials sealed with
// the same session key.
type Server struct {
	dir        string
	portPath   string
	pubKeyPath string
	privKey    string
	password   string
	tcpLn      net.Listener
	srv        *http.Server
	bindAddr   string
	stderr     io.Writer

	// notifications controls whether external (op://) resolves fire a desktop
	// notification. Enabled by default; WithNotifications(false) disables it.
	notifications bool

	// approvals gates credential resolution behind a host-side confirmation. Nil
	// (no WithApproval option) means no gate. The cache is created once and shared
	// across resolver reloads so approvals survive config changes.
	approvals *approvalCache

	commands CredentialFinder
	toolPath ToolResolver

	// mu guards resolver, which is swapped out when reload reports a config change.
	mu       sync.Mutex
	resolver *Resolver
	reload   ReloadFunc
}

// ReloadFunc is consulted at the start of each resolve request. It reports
// whether the on-disk configuration changed and, if so, returns the rebuilt
// credential finder and tool resolver to swap in. When nothing changed it
// returns changed=false and the other values are ignored.
type ReloadFunc func() (commands CredentialFinder, toolPath ToolResolver, changed bool)

// Option configures a Server at construction time.
type Option func(*Server)

// WithCommandLookup installs the credential finder that maps a command (tool
// + args) to the set of value-refs that apply. Without it, all resolve
// requests will fail with "no command resolver configured".
func WithCommandLookup(c CredentialFinder) Option {
	return func(s *Server) {
		s.commands = c
	}
}

// WithToolResolver installs a tool resolver for binny-managed tool paths. The resolver
// consults it when shelling out to helper binaries (notably `op`), so a
// binny-installed copy takes precedence over whatever PATH would surface.
func WithToolResolver(t ToolResolver) Option {
	return func(s *Server) {
		s.toolPath = t
	}
}

// WithCredentialPassword supplies the password used to decrypt enc:// values at
// resolve time. Without it, enc:// resolution fails (op:// and literal values
// still work). It is unrelated to the ephemeral transport key pair.
func WithCredentialPassword(password string) Option {
	return func(s *Server) {
		s.password = password
	}
}

// WithNotifications enables or disables desktop notifications fired when a
// command requires an external (op://) credential lookup. Notifications are
// enabled by default; headless servers and tests disable them.
func WithNotifications(enabled bool) Option {
	return func(s *Server) {
		s.notifications = enabled
	}
}

// notifier returns the Notifier the server's resolver should use: the desktop
// notifier when notifications are enabled, nil (disabled) otherwise.
func (s *Server) notifier() Notifier {
	if s.notifications {
		return DesktopNotifier
	}
	return nil
}

// WithApproval installs the host-side approval gate: each op:///enc:// value-ref
// must be confirmed by the user via prompter before it is resolved, and an
// approval is cached for ttl (clamped to [1m,10m]). When autoApprove is true the
// gate is disabled and every request resolves without prompting — intended for
// headless servers that explicitly opt in. Without this option there is no gate.
func WithApproval(ttl time.Duration, autoApprove bool, prompter Prompter) Option {
	return func(s *Server) {
		s.approvals = newApprovalCache(ttl, autoApprove, prompter)
	}
}

// WithReload installs a hook consulted at the start of each resolve request so
// the server can pick up edits to the configuration files without a restart.
// When the hook reports a change, its returned finder/tool-resolver replace the
// live ones.
func WithReload(fn ReloadFunc) Option {
	return func(s *Server) {
		s.reload = fn
	}
}

// New binds the TCP listener, mints a fresh in-memory RSA key pair (publishing
// only the public half under dir so clients can locate it), and writes the
// discovery file. The private key is never written to disk and is regenerated
// on every start.
func New(dir string, opts ...Option) (*Server, error) {
	if err := os.MkdirAll(dir, keyDirMode); err != nil {
		return nil, fmt.Errorf("unable to create %s: %w", dir, err)
	}

	pubKeyPath := filepath.Join(dir, pubKeyFileName)
	privKey, err := GenerateEphemeralKey(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("generating credential server key pair: %w", err)
	}

	portPath := filepath.Join(dir, portFileName)

	tcpLn, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind tcp listener: %w", err)
	}
	port := tcpLn.Addr().(*net.TCPAddr).Port

	if err := os.WriteFile(portPath, []byte(strconv.Itoa(port)+"\n"), serverInfoFileMode); err != nil {
		_ = tcpLn.Close()
		return nil, fmt.Errorf("failed to write port file: %w", err)
	}

	s := &Server{
		dir:           dir,
		portPath:      portPath,
		pubKeyPath:    pubKeyPath,
		privKey:       privKey,
		tcpLn:         tcpLn,
		bindAddr:      bindAddr,
		stderr:        os.Stderr,
		notifications: true,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.resolver = NewResolver(s.commands, s.password)
	s.resolver.SetToolPathResolver(s.toolPath)
	s.resolver.SetNotifier(s.notifier())
	s.resolver.SetApprovals(s.approvals)

	s.srv = &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

// BindAddr returns the bound TCP address
func (s *Server) BindAddr() string { return s.bindAddr }

// Port returns the actual TCP port the listener bound to (the configured
// address uses :0, so the real port is only known after New).
func (s *Server) Port() int {
	if s.tcpLn == nil {
		return 0
	}
	return s.tcpLn.Addr().(*net.TCPAddr).Port
}

// Serve runs the TCP listener and blocks until ctx is cancelled or SIGINT/
// SIGTERM is received, then gracefully shuts down and removes the port file.
// The signal handler guarantees the discovery file is cleaned up on ctrl-c
// even if callers forget to defer Close.
func (s *Server) Serve(ctx context.Context) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	errCh := make(chan error, 1)
	go func() {
		if err := s.srv.Serve(s.tcpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("tcp serve: %w", err)
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
	case sig := <-sigCh:
		log.Infof("received %s, shutting down credential server", sig)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.srv.Shutdown(shutdownCtx)
	_ = s.Close()
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// Close releases the listener and removes the discovery file. Safe to call
// more than once.
func (s *Server) Close() error {
	_ = s.tcpLn.Close()
	if s.portPath != "" {
		_ = os.Remove(s.portPath)
		s.portPath = ""
	}
	return nil
}

// currentResolver returns the resolver to service the next request, first
// applying any configuration change reported by the reload hook. The hook runs
// under the same lock that guards the swap so a reload mid-request can't race a
// concurrent resolve.
func (s *Server) currentResolver() *Resolver {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reload != nil {
		if commands, toolPath, changed := s.reload(); changed {
			s.commands = commands
			s.toolPath = toolPath
			s.resolver = NewResolver(commands, s.password)
			s.resolver.SetToolPathResolver(toolPath)
			s.resolver.SetNotifier(s.notifier())
			// Reuse the existing approval cache so approvals granted before the
			// reload are not forgotten when the config changes.
			s.resolver.SetApprovals(s.approvals)
			log.Infof("reloaded credential configuration")
		}
	}
	return s.resolver
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/resolve", s.handleResolve)
	return mux
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var env Envelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	plaintext, sessionKey, err := OpenEnvelope(s.privKey, env)
	if err != nil {
		log.Warnf("decrypting resolve envelope: %v", err)
		http.Error(w, "could not decrypt request", http.StatusBadRequest)
		return
	}

	var req resolveRequest
	if err := json.Unmarshal(plaintext, &req); err != nil {
		writeSealedError(w, sessionKey, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Command) == 0 {
		writeSealedError(w, sessionKey, http.StatusBadRequest, "command is required")
		return
	}

	resolver := s.currentResolver()

	log.Infof("resolve command: %s", strings.Join(req.Command, " "))

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	resolved, err := resolver.ResolveCommand(ctx, req.Command)
	if err != nil {
		log.Warnf("resolve command %q failed: %v", strings.Join(req.Command, " "), err)
		writeSealedError(w, sessionKey, http.StatusBadGateway, err.Error())
		return
	}

	body, err := json.Marshal(resolved)
	if err != nil {
		http.Error(w, "encoding response", http.StatusInternalServerError)
		return
	}
	sealed, err := SealResponse(sessionKey, body)
	if err != nil {
		http.Error(w, "encrypting response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sealed)
}

// writeSealedError emits an encrypted error message so error contents don't
// travel in plaintext. The status code is left in the HTTP header.
func writeSealedError(w http.ResponseWriter, sessionKey []byte, status int, msg string) {
	sealed, err := SealResponse(sessionKey, []byte(msg))
	if err != nil {
		http.Error(w, "encrypting response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(sealed)
}
