package binny

import (
	"context"
	"time"
)

type Tool interface {
	Name() string
	Installer
	VersionResolver
}

type Installer interface {
	InstallTo(ctx context.Context, version, destDir string) (string, error)
}

// ReferenceInstaller is an optional interface an Installer may implement to
// signal that InstallTo returns the absolute path of an existing executable
// (e.g. one found on PATH) rather than a binary staged for copying into the
// store. When IsReference returns true, the install flow records the path in
// place instead of moving it into the store.
type ReferenceInstaller interface {
	IsReference() bool
}

type VersionResolver interface {
	ResolveVersion(ctx context.Context, intent VersionIntent) (string, error)
	UpdateVersion(ctx context.Context, intent VersionIntent) (string, error)
}

type VersionIntent struct {
	Want       string
	Constraint string
	Cooldown   time.Duration
}
