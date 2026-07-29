package lookup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-homedir"
)

func TestLookPathExcludingSelf(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)

	selfResolved, err := filepath.EvalSymlinks(self)
	require.NoError(t, err)

	toolName := "fake-tool"

	// dir1: contains a symlink to the current binary (should be skipped)
	dir1 := t.TempDir()
	symlinkPath := filepath.Join(dir1, toolName)
	require.NoError(t, os.Symlink(selfResolved, symlinkPath))

	// dir2: contains the real tool
	dir2 := t.TempDir()
	realToolPath := filepath.Join(dir2, toolName)
	require.NoError(t, os.WriteFile(realToolPath, []byte("#!/bin/sh\necho real\n"), 0o755))

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", dir1+string(os.PathListSeparator)+dir2)
	defer func() { os.Setenv("PATH", origPath) }()

	got, err := lookPathExcludingSelf(toolName, nil)
	require.NoError(t, err)
	assert.Equal(t, realToolPath, got)
}

func TestLookPathExcludingSelf_AllSelf(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)

	selfResolved, err := filepath.EvalSymlinks(self)
	require.NoError(t, err)

	toolName := "fake-tool"

	// only directory contains a symlink to self
	dir := t.TempDir()
	require.NoError(t, os.Symlink(selfResolved, filepath.Join(dir, toolName)))

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", dir)
	defer func() { os.Setenv("PATH", origPath) }()

	_, err = lookPathExcludingSelf(toolName, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestLookPathExcludingSelf_NotFoundIsErrNotFound(t *testing.T) {
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir()) // empty dir, nothing to find
	defer func() { os.Setenv("PATH", origPath) }()

	_, err := lookPathExcludingSelf("definitely-not-a-real-tool", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestLookPathExcludingSelf_SearchDirs(t *testing.T) {
	toolName := "fake-tool"

	// the tool only exists in an additional search dir, not on PATH
	searchDir := t.TempDir()
	toolPath := filepath.Join(searchDir, toolName)
	require.NoError(t, os.WriteFile(toolPath, []byte("#!/bin/sh\necho hi\n"), 0o755))

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	defer func() { os.Setenv("PATH", origPath) }()

	got, err := lookPathExcludingSelf(toolName, []string{searchDir})
	require.NoError(t, err)
	assert.Equal(t, toolPath, got)
}

func TestFindExecutable_DirectPath(t *testing.T) {
	dir := t.TempDir()
	toolPath := filepath.Join(dir, "demo-tool")
	require.NoError(t, os.WriteFile(toolPath, []byte("#!/bin/sh\necho hi\n"), 0o755))

	got, err := findExecutable("ignored-name", toolPath, nil)
	require.NoError(t, err)
	assert.Equal(t, toolPath, got)
}

func TestFindExecutable_DirectPathTilde(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	homedir.Reset()
	t.Cleanup(homedir.Reset)

	toolPath := filepath.Join(home, "demo-tool")
	require.NoError(t, os.WriteFile(toolPath, []byte("#!/bin/sh\necho hi\n"), 0o755))

	got, err := findExecutable("ignored-name", "~/demo-tool", nil)
	require.NoError(t, err)
	assert.Equal(t, toolPath, got)
}

func TestFindExecutable_DirectPathMissing(t *testing.T) {
	_, err := findExecutable("ignored-name", filepath.Join(t.TempDir(), "nope"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not accessible")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestFindExecutable_DirectPathIsDir(t *testing.T) {
	dir := t.TempDir()
	_, err := findExecutable("ignored-name", dir, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "directory")
}

func TestLookPathExcludingSelf_NoSymlink(t *testing.T) {
	toolName := "fake-tool"

	dir := t.TempDir()
	toolPath := filepath.Join(dir, toolName)
	require.NoError(t, os.WriteFile(toolPath, []byte("#!/bin/sh\necho hi\n"), 0o755))

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", dir)
	defer func() { os.Setenv("PATH", origPath) }()

	got, err := lookPathExcludingSelf(toolName, nil)
	require.NoError(t, err)
	assert.Equal(t, toolPath, got)
}
