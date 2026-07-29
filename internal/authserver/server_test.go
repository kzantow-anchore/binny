package authserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEndToEnd_ResolveCommand verifies the wire protocol end-to-end: client
// sends a command, server matches it against the configured credentials, and
// returns the plaintext env + docker pair.
func TestEndToEnd_ResolveCommand(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	binnyDir := filepath.Join(homeDir, ".binny")
	require.NoError(t, os.MkdirAll(binnyDir, 0o700))

	cmd := fakeCommandLookup{cc: CommandCredentials{
		Env: []EnvBinding{{Key: "GITHUB_TOKEN", Token: "ghp_literal_readonly"}},
		Docker: &DockerRef{
			Username: "ci-bot",
			Password: "ci-bot-secret",
		},
	}}

	srv, err := New(binnyDir, WithCommandLookup(cmd))
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx) }()

	got, err := ResolveCommand(context.Background(), []string{"oras", "push", "ghcr.io/anchore/binny"})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"GITHUB_TOKEN": "ghp_literal_readonly"}, got.Env)
	require.NotNil(t, got.Docker)
	require.Equal(t, "ci-bot", got.Docker.Username)
	require.Equal(t, "ci-bot-secret", got.Docker.Secret)

	cancel()
	require.NoError(t, <-serveDone)
}

// TestEndToEnd_ResolveCommand_Reload verifies the server consults the reload
// hook before each request and swaps in the returned finder when it reports a
// change, so a later request sees the updated credentials.
func TestEndToEnd_ResolveCommand_Reload(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	binnyDir := filepath.Join(homeDir, ".binny")
	require.NoError(t, os.MkdirAll(binnyDir, 0o700))

	initial := fakeCommandLookup{cc: CommandCredentials{
		Env: []EnvBinding{{Key: "GITHUB_TOKEN", Token: "v1"}},
	}}
	updated := fakeCommandLookup{cc: CommandCredentials{
		Env: []EnvBinding{{Key: "GITHUB_TOKEN", Token: "v2"}},
	}}

	changeOnNextCall := false
	reload := func() (CredentialFinder, ToolResolver, bool) {
		if changeOnNextCall {
			changeOnNextCall = false
			return updated, nil, true
		}
		return nil, nil, false
	}

	srv, err := New(binnyDir, WithCommandLookup(initial), WithReload(reload))
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx) }()

	got, err := ResolveCommand(context.Background(), []string{"gh"})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"GITHUB_TOKEN": "v1"}, got.Env)

	changeOnNextCall = true
	got, err = ResolveCommand(context.Background(), []string{"gh"})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"GITHUB_TOKEN": "v2"}, got.Env, "expected reloaded credentials on the second request")

	cancel()
	require.NoError(t, <-serveDone)
}

// TestEndToEnd_ResolveCommand_NoCommandLookup verifies the server returns an
// error when no CredentialFinder was installed.
func TestEndToEnd_ResolveCommand_NoCommandLookup(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	binnyDir := filepath.Join(homeDir, ".binny")
	require.NoError(t, os.MkdirAll(binnyDir, 0o700))

	srv, err := New(binnyDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx) }()

	_, err = ResolveCommand(context.Background(), []string{"gh"})
	require.Error(t, err)

	cancel()
	require.NoError(t, <-serveDone)
}

// TestResolveCommand_NoServer ensures clients get a clean error when no server
// is discoverable, rather than silently succeeding.
func TestResolveCommand_NoServer(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	// No ~/.binny/port file exists.
	_, err := ResolveCommand(context.Background(), []string{"binny", "run", "anything"})
	require.Error(t, err)
}

// TestResolveCommand_EmptyCommand rejects an empty command client-side.
func TestResolveCommand_EmptyCommand(t *testing.T) {
	_, err := ResolveCommand(context.Background(), nil)
	require.Error(t, err)
}
