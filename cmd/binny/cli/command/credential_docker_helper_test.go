package command

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/binny/internal/authserver"
	binnyredact "github.com/anchore/binny/internal/redact"
	"github.com/anchore/go-logger/adapter/redact"
)

var redactStoreOnce sync.Once

// ensureRedactStore installs a redaction store so code paths that call
// redact.Add (e.g. startDockerCredPipe) don't panic under test.
func ensureRedactStore(t *testing.T) {
	t.Helper()
	redactStoreOnce.Do(func() {
		if binnyredact.Get() == nil {
			binnyredact.Set(redact.NewStore())
		}
	})
}

// shortSockDir returns a temp dir under /tmp that's short enough to stay
// inside the ~104-byte sun_path limit on macOS, which t.TempDir() can exceed.
func shortSockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "binny-sock-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestReadCredFromPipe(t *testing.T) {
	t.Run("env unset", func(t *testing.T) {
		t.Setenv(BinnyDockerCredPipeEnv, "")
		_, err := readCredFromPipe(context.Background())
		require.Error(t, err)
	})

	t.Run("dial fails when no listener", func(t *testing.T) {
		t.Setenv(BinnyDockerCredPipeEnv, filepath.Join(shortSockDir(t), "missing.sock"))
		_, err := readCredFromPipe(context.Background())
		require.Error(t, err)
	})

	t.Run("public key missing", func(t *testing.T) {
		ensureRedactStore(t)
		// a live socket with no published public key must fail closed rather than
		// fall back to a plaintext read.
		dir := shortSockDir(t)
		want := authserver.UsernameSecret{Username: "alice", Secret: "hunter2"}
		path, stop, err := startDockerCredPipe(dir, &want)
		require.NoError(t, err)
		t.Cleanup(stop)
		require.NoError(t, os.Remove(filepath.Join(dir, dockerCredPubKeyFileName)))

		t.Setenv(BinnyDockerCredPipeEnv, path)
		_, err = readCredFromPipe(context.Background())
		require.Error(t, err)
	})

	t.Run("round-trips encrypted credential", func(t *testing.T) {
		ensureRedactStore(t)
		want := authserver.UsernameSecret{Username: "alice", Secret: "hunter2"}

		dir := shortSockDir(t)
		path, stop, err := startDockerCredPipe(dir, &want)
		require.NoError(t, err)
		t.Cleanup(stop)

		t.Setenv(BinnyDockerCredPipeEnv, path)
		got, err := readCredFromPipe(context.Background())
		require.NoError(t, err)
		require.Equal(t, want, got)
	})
}
