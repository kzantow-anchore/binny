package command

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const credConfigV1 = `
credentials:
  registry:
    env:
      - key: TOKEN
        token: literal-v1
tools:
  - name: op
    version:
      want: current
    credentials:
      "*": registry
`

const credConfigV2 = `
credentials:
  registry:
    env:
      - key: TOKEN
        token: literal-v2-longer
tools:
  - name: op
    version:
      want: current
    credentials:
      "*": registry
`

func writeConfig(t *testing.T, path, contents string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
}

func TestLoadServeConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeConfig(t, path, credConfigV1)

	cfg, err := loadServeConfig([]string{path})
	require.NoError(t, err)

	require.Len(t, cfg.Tools, 1)
	assert.Equal(t, "op", cfg.Tools[0].Name)

	cc := cfg.Tools[0]
	require.NotNil(t, cfg.Credentials)
	cred, ok := cfg.Credentials["registry"]
	require.True(t, ok)
	require.Len(t, cred.Env, 1)
	assert.Equal(t, "TOKEN", cred.Env[0].Key)
	assert.Equal(t, "literal-v1", cred.Env[0].Token)
	assert.Equal(t, "registry", cc.Credentials["*"])
}

func TestConfigWatcherReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeConfig(t, path, credConfigV1)

	cfg, err := loadServeConfig([]string{path})
	require.NoError(t, err)

	w := newConfigWatcher(cfg)

	// nothing changed since the snapshot taken at construction
	_, _, changed := w.reload()
	assert.False(t, changed, "expected no reload when file is unchanged")

	// edit the file; the new content has a different size so the stamp differs
	// even if the mtime granularity is coarse
	writeConfig(t, path, credConfigV2)

	finder, resolver, changed := w.reload()
	require.True(t, changed, "expected a reload after the file changed")
	require.NotNil(t, finder)
	require.NotNil(t, resolver)

	cc := finder.GetCredentials([]string{"op"})
	require.Len(t, cc.Env, 1)
	assert.Equal(t, "TOKEN", cc.Env[0].Key)
	assert.Equal(t, "literal-v2-longer", cc.Env[0].Token, "reloaded finder should reflect the new token")

	// a subsequent call with no further edits reports no change
	_, _, changed = w.reload()
	assert.False(t, changed, "expected no reload on a second unchanged check")
}

func TestConfigWatcherReloadInvalidKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeConfig(t, path, credConfigV1)

	cfg, err := loadServeConfig([]string{path})
	require.NoError(t, err)
	w := newConfigWatcher(cfg)

	// write syntactically invalid YAML
	writeConfig(t, path, "credentials: [this is not valid: : :\n")

	_, _, changed := w.reload()
	assert.False(t, changed, "a config that fails to parse should not trigger a swap")
}
