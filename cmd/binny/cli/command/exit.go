package command

import "fmt"

// ToolExitError reports that a tool executed via `binny run` ran but exited
// non-zero. clio maps this error to the same process exit code (see
// WithMapExitCode in cli.New) so callers observe the status the tool produced.
type ToolExitError struct {
	Name string
	Code int
}

func (e *ToolExitError) Error() string {
	return fmt.Sprintf("%s exited with code %d", e.Name, e.Code)
}
