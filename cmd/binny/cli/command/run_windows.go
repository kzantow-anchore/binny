package command

import (
	"os"
	"os/exec"
)

func runOnPlatform(c *exec.Cmd) error {
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
