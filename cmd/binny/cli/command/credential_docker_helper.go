package command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anchore/binny/cmd/binny/cli/option"
	"github.com/anchore/binny/internal/authserver"
	"github.com/anchore/binny/internal/log"
	"github.com/anchore/binny/internal/redact"
	"github.com/anchore/clio"
)

// DockerHelperUse is the cobra Use string; also referenced by the wrapper
// script staged by `binny run` (see stageDockerCredHelper).
const DockerHelperUse = "docker-helper"

// DockerCredentialHelperName is the binary basename docker expects for the
// binny-managed credential helper (configured as `credsStore: binny` in the
// staged docker config.json). The wrapper script staged by `binny run` uses
// this name so docker can discover it on PATH.
//
//nolint:gosec // this is the credential helper name, not a credential
const DockerCredentialHelperName = "docker-credential-binny"

// dockerCredPipeReadTimeout caps how long the helper will wait when dialing
// and reading from the per-run named pipe.
const dockerCredPipeReadTimeout = 5 * time.Second

type CredentialDockerHelperConfig struct {
	option.Core `json:"" yaml:",inline" mapstructure:",squash"`
}

func CredentialDockerHelper(app clio.Application) *cobra.Command {
	cfg := &CredentialDockerHelperConfig{
		Core: option.DefaultCore(),
	}
	return app.SetupCommand(&cobra.Command{
		Hidden: true,
		Use:    DockerHelperUse + " <get|store|erase|list>",
		Short:  "Docker credential helper (invoked by docker, typically via docker-credential-binny)",
		Long: `Implements the docker credential helper protocol. Reads the named pipe
path from BINNY_DOCKER_HELPER_PIPE (set by binny run) and pulls the resolved
docker credential from it. The credential server is not contacted here; binny
run resolved the credential up front and serves it over an owner-only (0600)
socket.

This command is read-only: store and erase succeed silently because credentials
are managed by editing ~/.binny/config.yaml.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDockerHelper(cmd.Context(), args[0])
		},
	}, cfg)
}

func runDockerHelper(ctx context.Context, action string) error {
	log.Debugf("docker credential helper invoked: action=%s", action)
	switch action {
	case "get":
		return dockerHelperGet(ctx)
	case "list":
		_, err := os.Stdout.WriteString("{}\n")
		return err
	case "store", "erase":
		// Read-only helper: drain stdin so docker doesn't get a broken pipe,
		// then exit 0 without doing anything.
		_, _ = io.Copy(io.Discard, os.Stdin)
		return nil
	default:
		return fmt.Errorf("unknown docker credential helper action: %s", action)
	}
}

// dockerHelperGet reads a registry URL from stdin, pulls the resolved docker
// credential from the per-run named pipe referenced by BINNY_DOCKER_HELPER_PIPE,
// and emits the docker helper JSON response.
func dockerHelperGet(ctx context.Context) error {
	urlBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading server url from stdin: %w", err)
	}
	serverURL := strings.TrimSpace(string(urlBytes))
	log.Debugf("docker credential helper: get request for host=%q", serverURL)

	docker, err := readCredFromPipe(ctx)
	if err != nil {
		return err
	}
	log.Debugf("docker credential helper: returning credential for host=%q username=%s secret=%s", serverURL, redact.Preview(docker.Username), redact.Preview(docker.Secret))

	resp := map[string]string{
		"ServerURL": serverURL,
		"Username":  docker.Username,
		"Secret":    docker.Secret,
	}
	return json.NewEncoder(os.Stdout).Encode(resp)
}

// readCredFromPipe dials the named pipe whose path is held in
// BINNY_DOCKER_HELPER_PIPE and retrieves the docker credential served by `binny
// run`. The credential never crosses the socket in plaintext: this helper reads
// the ephemeral public key published next to the socket, wraps a fresh session
// key with it (SealEnvelope), sends that as a handshake, and decrypts the sealed
// reply (OpenResponse) with the session key only this process holds. The socket
// is also owner-only (0600).
func readCredFromPipe(ctx context.Context) (authserver.UsernameSecret, error) {
	path := os.Getenv(BinnyDockerCredPipeEnv)
	if path == "" {
		return authserver.UsernameSecret{}, fmt.Errorf("%s not set; docker-credential-binny must be invoked from a `binny run` subprocess", BinnyDockerCredPipeEnv)
	}

	pubKeyPath := filepath.Join(filepath.Dir(path), dockerCredPubKeyFileName)
	pubKey, err := authserver.LoadPublicKey(pubKeyPath)
	if err != nil {
		return authserver.UsernameSecret{}, fmt.Errorf("loading docker credential pipe public key: %w", err)
	}
	if pubKey == "" {
		return authserver.UsernameSecret{}, fmt.Errorf("docker credential pipe public key not found at %s", pubKeyPath)
	}

	log.Debugf("docker credential helper: dialing pipe %s", path)

	dialCtx, cancel := context.WithTimeout(ctx, dockerCredPipeReadTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", path)
	if err != nil {
		return authserver.UsernameSecret{}, fmt.Errorf("dialing docker credential pipe %s: %w", path, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(dockerCredPipeReadTimeout))

	// handshake: wrap a fresh session key with the pipe's public key so the
	// credential comes back sealed under a key only this process holds.
	env, sessionKey, err := authserver.SealEnvelope(pubKey, []byte("{}"))
	if err != nil {
		return authserver.UsernameSecret{}, fmt.Errorf("sealing docker credential handshake: %w", err)
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return authserver.UsernameSecret{}, fmt.Errorf("encoding docker credential handshake: %w", err)
	}
	if _, err := conn.Write(envBytes); err != nil {
		return authserver.UsernameSecret{}, fmt.Errorf("sending docker credential handshake: %w", err)
	}
	// half-close so the server reads the handshake to EOF, then reads the reply
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}

	raw, err := io.ReadAll(io.LimitReader(conn, 1<<16))
	if err != nil {
		return authserver.UsernameSecret{}, fmt.Errorf("reading docker credential pipe %s: %w", path, err)
	}
	log.Debugf("docker credential helper: received %d bytes from pipe", len(raw))

	var sresp authserver.SessionResponse
	if err := json.Unmarshal(raw, &sresp); err != nil {
		return authserver.UsernameSecret{}, fmt.Errorf("decoding docker credential response: %w", err)
	}
	plain, err := authserver.OpenResponse(sessionKey, sresp)
	if err != nil {
		return authserver.UsernameSecret{}, fmt.Errorf("decrypting docker credential response: %w", err)
	}

	var cred authserver.UsernameSecret
	if err := json.Unmarshal(plain, &cred); err != nil {
		return authserver.UsernameSecret{}, fmt.Errorf("decoding docker credential pipe payload: %w", err)
	}
	return cred, nil
}
