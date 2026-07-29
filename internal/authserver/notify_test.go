package authserver

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// A Resolver has no notifier unless one is installed, so tests never fire real
// desktop notifications. Tests that care about notification behavior install a
// capturedNotify via SetNotifier to record calls.

type capturedNotify struct {
	mu    sync.Mutex
	calls []capturedCall
}

type capturedCall struct {
	title   string
	message string
}

func (c *capturedNotify) fn(title, message string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, capturedCall{title: title, message: message})
	return nil
}

func (c *capturedNotify) snapshot() []capturedCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]capturedCall, len(c.calls))
	copy(out, c.calls)
	return out
}

// installCapture installs a recording notifier on r and returns it.
func installCapture(t *testing.T, r *Resolver) *capturedNotify {
	t.Helper()
	cap := &capturedNotify{}
	r.SetNotifier(cap.fn)
	return cap
}

func TestNotify_FiresWhenOpRefInEnv(t *testing.T) {
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Name: "some-credential-name",
		Env: []EnvBinding{
			{Key: "GH_TOKEN", Token: "op://Vault/Item/Token"},
		},
	}}
	r := NewResolver(cmd, "")
	cap := installCapture(t, r)
	_, err := r.ResolveCommand(context.Background(), []string{"gh", "auth", "status"})
	require.NoError(t, err)

	calls := cap.snapshot()
	require.Len(t, calls, 1)
	require.Contains(t, calls[0].title, "binny")
	require.Equal(t, `gh auth status
---------------
some-credential-name
  ↳ op://Vault/Item/Token`, calls[0].message)
}

func TestNotify_FiresWhenOpRefInDocker(t *testing.T) {
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Docker: &DockerRef{Username: "literal", Password: "op://Vault/Item/Secret"},
	}}
	r := NewResolver(cmd, "")
	cap := installCapture(t, r)
	_, err := r.ResolveCommand(context.Background(), []string{"docker", "push", "ghcr.io/foo"})
	require.NoError(t, err)

	calls := cap.snapshot()
	require.Len(t, calls, 1)
	require.True(t, strings.Contains(calls[0].message, "docker push"))
}

func TestNotify_SkipsWhenAllLiteral(t *testing.T) {
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Env:    []EnvBinding{{Key: "GH_TOKEN", Token: "ghp_literal"}},
		Docker: &DockerRef{Username: "user", Password: "pass"},
	}}
	r := NewResolver(cmd, "")
	cap := installCapture(t, r)
	_, err := r.ResolveCommand(context.Background(), []string{"gh"})
	require.NoError(t, err)

	require.Empty(t, cap.snapshot(), "no external refs → no notification")
}

func TestNotify_SkipsWhileApprovalDialogShown(t *testing.T) {
	// The very first resolve of a gated op:// ref prompts the user. The approval
	// dialog is itself the notification, so no desktop notification should fire.
	// The second resolve is served silently from the approval cache, so it
	// should notify.
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Name: "some-credential-name",
		Env:  []EnvBinding{{Key: "GH_TOKEN", Token: "op://Vault/Item/Token"}},
	}}
	r := NewResolver(cmd, "")
	cap := installCapture(t, r)
	r.SetApprovals(newApprovalCache(DefaultApprovalTTL, false, &fakePrompter{allow: true}))

	// first request: prompted (dialog shown) → no notification
	_, err := r.ResolveCommand(context.Background(), []string{"gh", "auth", "status"})
	require.NoError(t, err)
	require.Empty(t, cap.snapshot(), "prompting the user should not fire a notification")

	// second request: served silently from the cache → notification
	_, err = r.ResolveCommand(context.Background(), []string{"gh", "auth", "status"})
	require.NoError(t, err)
	require.Len(t, cap.snapshot(), 1, "a silent (cached-approved) resolve should notify")
}

func TestNotify_SkipsWhenDenied(t *testing.T) {
	// A denied credential resolves nothing, so no notification should fire.
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Name: "some-credential-name",
		Env:  []EnvBinding{{Key: "GH_TOKEN", Token: "op://Vault/Item/Token"}},
	}}
	r := NewResolver(cmd, "")
	cap := installCapture(t, r)
	r.SetApprovals(newApprovalCache(DefaultApprovalTTL, false, &fakePrompter{allow: false}))

	_, err := r.ResolveCommand(context.Background(), []string{"gh", "auth", "status"})
	require.NoError(t, err)
	require.Empty(t, cap.snapshot(), "a denied credential should not fire a notification")
}

func TestNotify_SkipsWhenOnlyEncRef(t *testing.T) {
	// enc:// stays local — no biometric prompt, no shell-out — so no
	// notification is needed.
	cmd := fakeCommandLookup{cc: CommandCredentials{
		Env: []EnvBinding{{Key: "X", Token: encPrefix + "abc"}},
	}}
	r := NewResolver(cmd, "")
	cap := installCapture(t, r)
	_, err := r.ResolveCommand(context.Background(), []string{"any"})
	require.NoError(t, err)

	require.Empty(t, cap.snapshot(), "enc:// alone should not notify")
}
