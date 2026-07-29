package lookup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstaller_InstallTo(t *testing.T) {
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "demo-tool")
	require.NoError(t, os.WriteFile(srcPath, []byte("#!/bin/sh\necho hi\n"), 0o755))

	destDir := t.TempDir()

	cfg := InstallerParameters{Name: "demo-tool"}
	installer := NewInstaller(cfg)
	require.True(t, installer.IsReference())
	installer.lookupPath = func(name string) (string, error) {
		assert.Equal(t, "demo-tool", name)
		return srcPath, nil
	}

	got, err := installer.InstallTo(context.Background(), "1.0.0", destDir)
	require.NoError(t, err)

	// the absolute (symlink-resolved) source path is returned and nothing is
	// copied into destDir
	assert.True(t, filepath.IsAbs(got))
	wantResolved, err := filepath.EvalSymlinks(srcPath)
	require.NoError(t, err)
	assert.Equal(t, wantResolved, got)

	entries, err := os.ReadDir(destDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestInstaller_InstallTo_LookupFails(t *testing.T) {
	cfg := InstallerParameters{Name: "missing-tool"}
	installer := NewInstaller(cfg)
	installer.lookupPath = func(_ string) (string, error) {
		return "", fmt.Errorf("not found")
	}

	_, err := installer.InstallTo(context.Background(), "1.0.0", t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing-tool")
}

func TestInstaller_InstallTo_NoName(t *testing.T) {
	installer := NewInstaller(InstallerParameters{})

	_, err := installer.InstallTo(context.Background(), "1.0.0", t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestInstaller_InstallTo_DirectPath(t *testing.T) {
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "demo-tool")
	require.NoError(t, os.WriteFile(srcPath, []byte("#!/bin/sh\necho hi\n"), 0o755))

	// no name; a direct path is sufficient
	installer := NewInstaller(InstallerParameters{Path: srcPath})

	got, err := installer.InstallTo(context.Background(), "1.0.0", t.TempDir())
	require.NoError(t, err)

	assert.True(t, filepath.IsAbs(got))
	wantResolved, err := filepath.EvalSymlinks(srcPath)
	require.NoError(t, err)
	assert.Equal(t, wantResolved, got)
}
