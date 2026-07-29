package command

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDockerCredHelperWrapper_Unix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix wrapper format")
	}

	name, body := dockerCredHelperWrapper("/abs/path/to/binny")
	require.Equal(t, DockerCredentialHelperName, name)
	require.Equal(t, "#!/bin/sh\nexec '/abs/path/to/binny' credential "+DockerHelperUse+" \"$@\"\n", body)
}

func TestDockerCredHelperWrapper_UnixEscapesQuotes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix wrapper format")
	}

	// A single quote in the path must be escaped to '\'' so the surrounding
	// single-quoted string can't be broken out of.
	_, body := dockerCredHelperWrapper("/weird/it's/binny")
	require.Contains(t, body, `'/weird/it'\''s/binny'`)
}

func TestDockerCredHelperWrapper_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows wrapper format")
	}

	name, body := dockerCredHelperWrapper(`C:\bin\binny.exe`)
	require.Equal(t, DockerCredentialHelperName+".cmd", name)
	require.Equal(t, "@echo off\r\n\"C:\\bin\\binny.exe\" credential "+DockerHelperUse+" %*\r\n", body)
}

func TestStageDockerCredHelper_WritesExecutableWrapper(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, stageDockerCredHelper(dir))

	helperName := DockerCredentialHelperName
	if runtime.GOOS == "windows" {
		helperName += ".cmd"
	}
	helperPath := filepath.Join(dir, helperName)

	info, err := os.Stat(helperPath)
	require.NoError(t, err)
	require.False(t, info.IsDir())
	// POSIX execute bit must be set so docker can invoke it.
	if runtime.GOOS != "windows" {
		require.NotZero(t, info.Mode().Perm()&0o111, "wrapper must be executable; got mode %v", info.Mode())
	}
}

func TestStageDockerCredHelper_WrapperDispatchesToBinny(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("execution test uses /bin/sh")
	}

	// Build a stub "binny" that simply prints its args. The wrapper should
	// invoke it as `<stub> credential docker-helper <user-args...>`, so we can
	// assert dispatch happened by inspecting stdout.
	stubDir := t.TempDir()
	stub := filepath.Join(stubDir, "binny-stub")
	require.NoError(t, os.WriteFile(stub, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0o755))

	// dockerCredHelperWrapper is what the live code uses; call it directly
	// with the stub path so we don't have to fake os.Executable().
	dir := t.TempDir()
	name, body := dockerCredHelperWrapper(stub)
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755))

	out, err := exec.Command(filepath.Join(dir, name), "get").Output()
	require.NoError(t, err)
	got := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	require.Equal(t, []string{"credential", DockerHelperUse, "get"}, got)
}

func TestErrExecutableNotFound(t *testing.T) {
	err := errExecutableNotFound("docker")
	require.EqualError(t, err, "executable not found: docker")
}

func TestIsExecutableFile(t *testing.T) {
	dir := t.TempDir()

	execPath := filepath.Join(dir, "runnable")
	require.NoError(t, os.WriteFile(execPath, []byte("#!/bin/sh\necho hi\n"), 0o755))

	nonExecPath := filepath.Join(dir, "data")
	require.NoError(t, os.WriteFile(nonExecPath, []byte("plain"), 0o644))

	missingPath := filepath.Join(dir, "gone")

	require.True(t, isExecutableFile(execPath), "an executable regular file should be reported executable")
	require.False(t, isExecutableFile(missingPath), "a missing file should not be reported executable")
	require.False(t, isExecutableFile(dir), "a directory should not be reported executable")

	// on non-Windows the execute bit is required; Windows ignores it
	if runtime.GOOS == "windows" {
		require.True(t, isExecutableFile(nonExecPath))
	} else {
		require.False(t, isExecutableFile(nonExecPath), "a file without the execute bit should not be reported executable")
	}
}

func TestPrependPath(t *testing.T) {
	sep := string(os.PathListSeparator)
	tests := []struct {
		name, existing, dir, want string
	}{
		{name: "empty existing", existing: "", dir: "/new", want: "/new"},
		{name: "empty dir", existing: "/a" + sep + "/b", dir: "", want: "/a" + sep + "/b"},
		{name: "normal prepend", existing: "/a" + sep + "/b", dir: "/new", want: "/new" + sep + "/a" + sep + "/b"},
		{name: "dir already first", existing: "/new" + sep + "/a", dir: "/new", want: "/new" + sep + "/a"},
		{name: "dir already present elsewhere", existing: "/a" + sep + "/new" + sep + "/b", dir: "/new", want: "/a" + sep + "/new" + sep + "/b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, prependPath(tc.existing, tc.dir))
		})
	}
}
