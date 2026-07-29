package authserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ResolveCommand asks a running binny credential server to look up and resolve
// every credential that applies to the given command (tool + args). The server
// matches the command against its configured tool credentials, resolves each
// cred-ref to plaintext (op://, enc://, or literal), and returns the env vars
// and docker credential pair the caller should apply. The client never names
// scopes or cred-refs itself.
//
// The request and response are encrypted with the server's RSA public key
// (loaded from ~/.binny/.key.pub) wrapping an ephemeral AES-256-GCM session
// key.
func ResolveCommand(ctx context.Context, command []string) (ResolvedCredentials, error) {
	if len(command) == 0 {
		return ResolvedCredentials{}, fmt.Errorf("command is required")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ResolvedCredentials{}, fmt.Errorf("unable to resolve home directory: %w", err)
	}
	dir := filepath.Join(home, ".binny")

	port, err := readPort(filepath.Join(dir, portFileName))
	if err != nil {
		return ResolvedCredentials{}, fmt.Errorf("discovering credential server: %w", err)
	}

	pubKeyPath := filepath.Join(dir, pubKeyFileName)
	pubKey, err := LoadPublicKey(pubKeyPath)
	if err != nil || pubKey == "" {
		return ResolvedCredentials{}, fmt.Errorf("unable to load cred server public key (%s); is the server running? %v", pubKeyPath, err)
	}

	body, err := json.Marshal(resolveRequest{Command: command})
	if err != nil {
		return ResolvedCredentials{}, fmt.Errorf("encoding resolve request: %w", err)
	}
	env, sessionKey, err := SealEnvelope(pubKey, body)
	if err != nil {
		return ResolvedCredentials{}, fmt.Errorf("encrypting resolve request: %w", err)
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return ResolvedCredentials{}, fmt.Errorf("encoding resolve envelope: %w", err)
	}

	raw, status, err := postResolve(ctx, port, envBytes)
	if err != nil {
		return ResolvedCredentials{}, err
	}

	plain, sealedErr := unsealResponse(sessionKey, raw)
	if status != http.StatusOK {
		if sealedErr != nil {
			return ResolvedCredentials{}, fmt.Errorf("credential server returned %d: %s", status, strings.TrimSpace(string(raw)))
		}
		return ResolvedCredentials{}, fmt.Errorf("credential server returned %d: %s", status, strings.TrimSpace(string(plain)))
	}
	if sealedErr != nil {
		return ResolvedCredentials{}, fmt.Errorf("decrypting resolve response: %w", sealedErr)
	}

	var out ResolvedCredentials
	if err := json.Unmarshal(plain, &out); err != nil {
		return ResolvedCredentials{}, fmt.Errorf("decoding resolve response: %w", err)
	}
	return out, nil
}

// postResolve POSTs the sealed envelope to the credential server's /resolve
// endpoint and returns the raw (still-sealed) response body and HTTP status.
// The server is addressed by BINNY_HOST (default loopback) and the port the
// running server published under ~/.binny.
func postResolve(ctx context.Context, port int, envBytes []byte) ([]byte, int, error) {
	// Generous timeout because the server may shell out to `op` which can
	// prompt for biometric auth.
	reqCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	host := os.Getenv("BINNY_HOST")
	if host == "" {
		host = "127.0.0.1"
	}

	url := fmt.Sprintf("http://%s:%d/resolve", host, port)
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(envBytes)) //nolint:gosec // G704: target is trusted local credential-server config (BINNY_HOST + the port file the server wrote), not untrusted input
	if err != nil {
		return nil, 0, fmt.Errorf("building resolve request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq) //nolint:gosec // G704: see above; target is the trusted local credential server, not untrusted input
	if err != nil {
		return nil, 0, fmt.Errorf("contacting credential server at %s:%d: %w", host, port, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("reading resolve response: %w", err)
	}
	return raw, resp.StatusCode, nil
}

// unsealResponse attempts to decode raw as a SessionResponse and decrypt it
// with sessionKey. Returns the plaintext on success or an error if raw is not
// a sealed response (e.g. a plain-text HTTP error string from an early
// failure in the server handler).
func unsealResponse(sessionKey, raw []byte) ([]byte, error) {
	var sresp SessionResponse
	if err := json.Unmarshal(raw, &sresp); err != nil {
		return nil, err
	}
	if sresp.Payload == "" {
		return nil, fmt.Errorf("response is not a sealed envelope")
	}
	return OpenResponse(sessionKey, sresp)
}

func readPort(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// Available reports whether a binny credential server appears reachable from
// this process: a port file exists under ~/.binny. (The host is resolved from
// BINNY_HOST, defaulting to loopback, only when a request is actually made.)
// Callers can use this to decide whether to route credential resolution through
// the server instead of the local config.
func Available() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(home, ".binny", portFileName)); err != nil {
		return false
	}
	return true
}
