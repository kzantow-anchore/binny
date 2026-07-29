package lookup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/anchore/go-homedir"
)

// ErrNotFound indicates the executable a lookup tool references could not be
// located (not on PATH, not in the configured search paths, or the configured
// direct path is missing). Callers can detect this with errors.Is to surface a
// concise "executable not found" message instead of the verbose lookup chain.
var ErrNotFound = errors.New("executable not found")

// findExecutable resolves the executable for a lookup tool. When directPath is
// set it is used verbatim (after validating it exists and is a file); otherwise
// searchDirs followed by PATH are searched via lookPathExcludingSelf. A leading
// tilde in directPath or any searchDir is expanded to the user's home directory.
func findExecutable(name, directPath string, searchDirs []string) (string, error) {
	if directPath != "" {
		expanded, err := homedir.Expand(directPath)
		if err != nil {
			return "", fmt.Errorf("failed to expand configured path %q: %w", directPath, err)
		}
		fi, err := os.Stat(expanded)
		if err != nil {
			return "", fmt.Errorf("%w: configured path %q is not accessible: %v", ErrNotFound, expanded, err)
		}
		if fi.IsDir() {
			return "", fmt.Errorf("configured path %q is a directory, not an executable", expanded)
		}
		return expanded, nil
	}
	return lookPathExcludingSelf(name, searchDirs)
}

// lookPathExcludingSelf searches searchDirs followed by PATH for the named
// program, skipping any candidate that resolves (through symlinks) to the
// currently running binary. This prevents infinite loops when binny is invoked
// via a symlink whose basename matches a "lookup"-type tool (e.g. `gh` → `binny`).
func lookPathExcludingSelf(name string, searchDirs []string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		// can't determine self, fall back to normal lookup
		return exec.LookPath(name)
	}
	selfResolved, err := filepath.EvalSymlinks(self)
	if err != nil {
		selfResolved = self
	}
	selfAbs, err := filepath.Abs(selfResolved)
	if err != nil {
		return exec.LookPath(name)
	}

	var dirs []string
	for _, dir := range searchDirs {
		// a leading tilde in a configured search dir resolves to the home directory
		if expanded, err := homedir.Expand(dir); err == nil {
			dir = expanded
		}
		dirs = append(dirs, dir)
	}
	dirs = append(dirs, filepath.SplitList(os.Getenv("PATH"))...)
	for _, dir := range dirs {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, name)

		// G703: candidate is <search dir or PATH entry>/<tool name>; resolving a
		// configured tool by name across PATH is exactly the intended behavior of
		// this function, not attacker-controlled path traversal.
		//nolint:gosec // G703: intentional PATH/search-dir resolution of a configured tool name
		fi, err := os.Stat(candidate)
		if err != nil || fi.IsDir() {
			continue
		}
		if fi.Mode()&0111 == 0 {
			continue
		}

		// resolve symlinks to see if this candidate points back to us
		candidateResolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			candidateResolved = candidate
		}
		candidateAbs, err := filepath.Abs(candidateResolved)
		if err != nil {
			candidateAbs = candidateResolved
		}
		if candidateAbs == selfAbs {
			continue
		}

		return candidate, nil
	}

	return "", fmt.Errorf("%w: %q not found in PATH or configured search paths (excluding self)", ErrNotFound, name)
}
