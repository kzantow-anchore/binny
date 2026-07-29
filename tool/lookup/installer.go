package lookup

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/anchore/binny"
	"github.com/anchore/binny/internal/log"
)

var (
	_ binny.Installer          = (*Installer)(nil)
	_ binny.ReferenceInstaller = (*Installer)(nil)
)

type InstallerParameters struct {
	Name string `json:"name" yaml:"name" mapstructure:"name"`
	// Path is a direct path to the executable; when set, PATH is not searched.
	Path string `json:"path" yaml:"path" mapstructure:"path"`
	// SearchPaths are additional directories searched (in order) ahead of PATH.
	SearchPaths []string `json:"search-paths" yaml:"search-paths" mapstructure:"search-paths"`
}

type Installer struct {
	config     InstallerParameters
	lookupPath func(name string) (string, error)
}

// IsReference always reports true: the lookup installer records the existing
// executable at its real location rather than copying it into the store. It
// satisfies binny.ReferenceInstaller.
func (i Installer) IsReference() bool {
	return true
}

func NewInstaller(cfg InstallerParameters) Installer {
	return Installer{
		config: cfg,
		lookupPath: func(name string) (string, error) {
			return findExecutable(name, cfg.Path, cfg.SearchPaths)
		},
	}
}

// InstallTo resolves the executable on PATH and returns its absolute path. The
// binary is not copied into destDir; the returned path points at the real
// executable so the store can reference (and hash) it in place.
func (i Installer) InstallTo(ctx context.Context, version, _ string) (string, error) {
	if i.config.Name == "" && i.config.Path == "" {
		return "", fmt.Errorf("lookup installer requires a 'name' or 'path' parameter")
	}

	lgr := log.FromContext(ctx)
	lgr.WithFields("tool", i.config.Name).Debug("looking up executable in PATH")

	sourcePath, err := i.lookupPath(i.config.Name)
	if err != nil {
		return "", fmt.Errorf("failed to find %q in PATH: %w", i.config.Name, err)
	}

	resolved, err := filepath.EvalSymlinks(sourcePath)
	if err != nil {
		// fall back to the original path if resolving symlinks fails
		resolved = sourcePath
	}

	abs, err := filepath.Abs(resolved)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute path for %q: %w", resolved, err)
	}

	lgr.WithFields("tool", i.config.Name, "source", abs, "version", version).Trace("referencing executable from PATH")

	return abs, nil
}
