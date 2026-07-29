//go:build linux || darwin

package command

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"

	"github.com/anchore/binny/internal/log"
)

func runOnPlatform(c *exec.Cmd) error {
	log.Debugf("executing command: %s %s", c.Path, c.Args)
	ptmx, err := pty.Start(c)
	if err != nil {
		return err
	}

	// make sure to close the pty at the end
	defer func() { _ = ptmx.Close() }() // best effort

	// only manage pty size and raw mode when stdin is an actual terminal; in
	// non-interactive environments (piped input, devcontainers, CI) these ioctls
	// fail with "inappropriate ioctl for device".
	if term.IsTerminal(int(os.Stdin.Fd())) {
		// handle pty size
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGWINCH)
		go func() {
			for range ch {
				if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
					log.Warnf("error resizing pty: %s", err)
				}
			}
		}()
		ch <- syscall.SIGWINCH                        // initial resize
		defer func() { signal.Stop(ch); close(ch) }() // cleanup signals when done

		// Set stdin in raw mode.
		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }() // best effort
	}

	// copy stdin to the pty and the pty to stdout. The goroutine will keep reading until the next keystroke before returning.
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, ptmx)

	// wait for the process to exit so its exit code can be propagated to the
	// caller; without this the wrapped tool's failure would be reported as success.
	return c.Wait()
}
