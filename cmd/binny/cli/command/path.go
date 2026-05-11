package command

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/anchore/binny"
	"github.com/anchore/binny/cmd/binny/cli/option"
	"github.com/anchore/binny/internal/bus"
	"github.com/anchore/binny/tool"
	"github.com/anchore/clio"
)

func Path(app clio.Application) *cobra.Command {
	cfg := &InstallConfig{
		StopOnError: false,
		Core:        option.DefaultCore(),
	}

	return app.SetupCommand(&cobra.Command{
		Use:   "path NAME",
		Short: "Print the absolute path to a tool's binary, installing it first if needed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPath(cmd.Context(), *cfg, args[0])
		},
	}, cfg)
}

func runPath(ctx context.Context, cmdCfg InstallConfig, name string) error {
	opt := cmdCfg.Tools.GetOption(name)
	if opt == nil {
		return fmt.Errorf("no tool configured with name: %s", name)
	}

	store, err := binny.NewStore(cmdCfg.Root)
	if err != nil {
		return err
	}

	t, intent, err := opt.ToTool(cmdCfg.toolOptions())
	if err != nil {
		return fmt.Errorf("failed to resolve tool config %q: %w", opt.Name, err)
	}

	if err := tool.Install(ctx, t, *intent, store, tool.VerifyConfig{
		VerifyXXH64Digest:  true,
		VerifySHA256Digest: cmdCfg.VerifySHA256Digest,
	}); err != nil && !errors.Is(err, tool.ErrAlreadyInstalled) {
		return fmt.Errorf("failed to install tool %q: %w", t.Name(), err)
	}

	entries := store.GetByName(name)
	switch len(entries) {
	case 0:
		return fmt.Errorf("no tool installed with name: %s", name)
	case 1:
		// pass
	default:
		return fmt.Errorf("multiple tools installed with name: %s", name)
	}

	fullPath, err := filepath.Abs(entries[0].Path())
	if err != nil {
		return fmt.Errorf("unable to resolve path to tool: %w", err)
	}

	bus.Report(fullPath)
	return nil
}
