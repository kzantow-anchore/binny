package authserver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// approved enc:// values resolve; the prompter is consulted for the gated ref
// but not for the plain literal.
func TestResolver_Gate_ApprovedResolves(t *testing.T) {
	const pw = "test-pw"
	enc, err := EncryptPassword(pw, []byte("sealed-token"))
	require.NoError(t, err)

	cmd := fakeCommandLookup{cc: CommandCredentials{
		Name: "github",
		Env: []EnvBinding{
			{Key: "LITERAL", Token: "plain"},
			{Key: "SEALED", Token: enc},
		},
	}}

	p := &fakePrompter{allow: true}
	r := NewResolver(cmd, pw)
	r.SetApprovals(newApprovalCache(DefaultApprovalTTL, false, p))

	got, err := r.ResolveCommand(context.Background(), []string{"gh", "auth"})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"LITERAL": "plain", "SEALED": "sealed-token"}, got.Env)
	// only the enc:// ref is gated; the literal is never sent to the prompter
	require.Equal(t, 1, p.count())
}

// a denied gated ref is skipped (fail-closed for that value) while ungated
// literals still resolve.
func TestResolver_Gate_DeniedIsSkipped(t *testing.T) {
	const pw = "test-pw"
	enc, err := EncryptPassword(pw, []byte("sealed-token"))
	require.NoError(t, err)

	cmd := fakeCommandLookup{cc: CommandCredentials{
		Name: "github",
		Env: []EnvBinding{
			{Key: "LITERAL", Token: "plain"},
			{Key: "SEALED", Token: enc},
		},
	}}

	p := &fakePrompter{allow: false}
	r := NewResolver(cmd, pw)
	r.SetApprovals(newApprovalCache(DefaultApprovalTTL, false, p))

	got, err := r.ResolveCommand(context.Background(), []string{"gh", "auth"})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"LITERAL": "plain"}, got.Env)
	require.Equal(t, 1, p.count())
}
