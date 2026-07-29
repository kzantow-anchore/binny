package authserver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakeCommandLookup struct{ cc CommandCredentials }

func (f fakeCommandLookup) GetCredentials([]string) CommandCredentials { return f.cc }

func TestResolver_ResolveCommand_EnvAndDocker(t *testing.T) {
	const pw = "test-pw"
	enc, err := EncryptPassword(pw, []byte("sealed-token"))
	require.NoError(t, err)

	cmd := fakeCommandLookup{cc: CommandCredentials{
		Env: []EnvBinding{
			{Key: "GITHUB_TOKEN", Token: "ghp_literal"},
			{Key: "SEALED_SECRET", Token: enc},
		},
		Docker: &DockerRef{
			Username: "ci-user",
			Password: "ci-pass",
		},
	}}

	r := NewResolver(cmd, pw)
	got, err := r.ResolveCommand(context.Background(), []string{"gh", "auth", "status"})
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"GITHUB_TOKEN":  "ghp_literal",
		"SEALED_SECRET": "sealed-token",
	}, got.Env)
	require.NotNil(t, got.Docker)
	require.Equal(t, "ci-user", got.Docker.Username)
	require.Equal(t, "ci-pass", got.Docker.Secret)
}

func TestResolver_ResolveCommand_LaterEnvBindingWins(t *testing.T) {
	// Two bindings for the same key — the second one (e.g. from the more
	// specific tool-pattern match) wins via map overwrite.
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Env: []EnvBinding{
			{Key: "GH_TOKEN", Token: "broad-token"},
			{Key: "GH_TOKEN", Token: "specific-token"},
		},
	}}
	r := NewResolver(cmd, "")
	got, err := r.ResolveCommand(context.Background(), []string{"gh"})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"GH_TOKEN": "specific-token"}, got.Env)
}

func TestResolver_ResolveCommand_EncRequiresPassword(t *testing.T) {
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Env: []EnvBinding{{Key: "X", Token: encPrefix + "abc"}},
	}}
	r := NewResolver(cmd, "")
	got, err := r.ResolveCommand(context.Background(), []string{"any"})
	require.NoError(t, err)
	// No password → enc entry is skipped; output env is nil.
	require.Nil(t, got.Env)
}

func TestResolver_ResolveCommand_EncRejectsBadBase64(t *testing.T) {
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Env: []EnvBinding{{Key: "X", Token: encPrefix + "!!!not-base64!!!"}},
	}}
	r := NewResolver(cmd, "test-pw")
	got, err := r.ResolveCommand(context.Background(), []string{"any"})
	require.NoError(t, err)
	require.Nil(t, got.Env)
}

func TestResolver_ResolveCommand_SkipsBrokenEnvEntry(t *testing.T) {
	// A broken enc:// entry must not abort the rest of the env map.
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Env: []EnvBinding{
			{Key: "GOOD", Token: "literal-good"},
			{Key: "BAD", Token: encPrefix + "abc"}, // no key loaded → resolveEnc errors
		},
	}}
	r := NewResolver(cmd, "")
	got, err := r.ResolveCommand(context.Background(), []string{"any"})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"GOOD": "literal-good"}, got.Env)
	require.Nil(t, got.Docker)
}

func TestResolver_ResolveCommand_DockerLiteralAndOpStillResolves(t *testing.T) {
	// A literal username + literal password should pass through unchanged.
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Docker: &DockerRef{Username: "api", Password: "literal-secret"},
	}}
	r := NewResolver(cmd, "")
	got, err := r.ResolveCommand(context.Background(), []string{"docker"})
	require.NoError(t, err)
	require.NotNil(t, got.Docker)
	require.Equal(t, "api", got.Docker.Username)
	require.Equal(t, "literal-secret", got.Docker.Secret)
}

func TestResolver_ResolveCommand_DockerNilWhenBothEmpty(t *testing.T) {
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Docker: &DockerRef{},
	}}
	r := NewResolver(cmd, "")
	got, err := r.ResolveCommand(context.Background(), []string{"docker"})
	require.NoError(t, err)
	require.Nil(t, got.Docker)
}

func TestResolver_ResolveCommand_NoCommandFinder(t *testing.T) {
	r := NewResolver(nil, "")
	_, err := r.ResolveCommand(context.Background(), []string{"any"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no command resolver")
}

func TestResolver_ResolveValue_OpURI(t *testing.T) {
	// op:// values shell out; we can't actually invoke `op`, but reaching
	// resolveOp at all proves the scheme dispatch happened.
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Env: []EnvBinding{{Key: "X", Token: "op://Vault/Item/Field"}},
	}}
	r := NewResolver(cmd, "")
	got, err := r.ResolveCommand(context.Background(), []string{"x"})
	require.NoError(t, err)
	// Resolution failed → entry skipped → no env emitted.
	require.Nil(t, got.Env)
}
