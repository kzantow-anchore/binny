package credentialserve

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHostClientResolvesAllValueRefKinds spawns the credential server against
// the mock-backed config and runs `binny run mocktool` as a host client. The
// mock tool prints its environment, so we can assert the exact plaintext binny
// injected for every value-ref kind: op:// (via the mock op binary), enc://
// (in-process RSA decrypt), and literal.
func Test_HostClientResolvesAllValueRefKinds(t *testing.T) {
	binny := buildHostBinny(t)
	h := newHarness(t)
	h.startServer(binny)

	// `binny run` disables flag parsing (args pass through to the tool), so the
	// config is supplied via env rather than -c.
	stdout, stderr, err := h.runBinny(binny, []string{"BINNY_CONFIG=" + h.configPath}, "run", "mocktool")
	require.NoError(t, err, "stderr:\n%s", stderr)

	env := parseEnv(stdout)

	assert.Equal(t, opEnvSecret, env["OP_SECRET"], "op:// value should resolve via the mock op binary")
	assert.Equal(t, encSecret, env["ENC_SECRET"], "enc:// value should resolve via password-based decrypt")
	assert.Equal(t, literalSecret, env["LIT_SECRET"], "literal value should pass through unchanged")

	// A broken op:// ref must be skipped (logged + dropped), not abort the rest.
	_, present := env["OP_MISSING"]
	assert.False(t, present, "unresolvable op:// ref should be dropped, not injected")

	// The base "*" pattern matched, so the more-specific push secret must not leak in.
	_, pushPresent := env["PUSH_SECRET"]
	assert.False(t, pushPresent, "push-specific credential should not match a bare invocation")
}

// TestHostClientArgSpecificity verifies the most-specific credential pattern
// wins: invoking the tool with `push ghcr.io/...` args must inject the push
// credential and only the push credential.
func TestHostClientArgSpecificity(t *testing.T) {
	binny := buildHostBinny(t)
	h := newHarness(t)
	h.startServer(binny)

	stdout, stderr, err := h.runBinny(binny, []string{"BINNY_CONFIG=" + h.configPath}, "run", "mocktool", "push", "ghcr.io/anchore/binny")
	require.NoError(t, err, "stderr:\n%s", stderr)

	env := parseEnv(stdout)
	assert.Equal(t, pushSecret, env["PUSH_SECRET"], "the push-specific pattern should win")

	_, basePresent := env["OP_SECRET"]
	assert.False(t, basePresent, "only the most-specific matching credential should apply")
}

// TestHostClientDockerCredential verifies the docker username/password pair
// (both op://-backed) is resolved. `credential check` reports it as a redacted
// fingerprint, confirming server-side docker resolution succeeded.
func TestHostClientDockerCredential(t *testing.T) {
	binny := buildHostBinny(t)
	h := newHarness(t)
	h.startServer(binny)

	stdout, stderr, err := h.runBinny(binny, []string{"BINNY_CONFIG=" + h.configPath}, "credential", "check", "mocktool")
	require.NoError(t, err, "stderr:\n%s", stderr)

	assert.Contains(t, stdout, "docker: username=", "docker username should resolve")
	assert.Contains(t, stdout, "password=", "docker password should resolve")
	// env refs should also be reported (redacted) by check
	assert.Contains(t, stdout, "OP_SECRET=")
	assert.Contains(t, stdout, "ENC_SECRET=")
	assert.Contains(t, stdout, "LIT_SECRET=")
}

// TestHostClientApprovalDenied verifies the approval gate: when the host denies
// the request, gated value-refs (op://, enc://) are skipped and never injected,
// while ungated literals still pass through. This exercises the gate end-to-end
// without popping a real dialog (the server uses the test-only deny prompter).
func TestHostClientApprovalDenied(t *testing.T) {
	binny := buildHostBinny(t)
	h := newHarness(t)
	h.startServerWithApproval(binny, "deny")

	stdout, stderr, err := h.runBinny(binny, []string{"BINNY_CONFIG=" + h.configPath}, "run", "mocktool")
	require.NoError(t, err, "stderr:\n%s", stderr)

	env := parseEnv(stdout)

	// gated refs are denied and dropped
	_, opPresent := env["OP_SECRET"]
	assert.False(t, opPresent, "denied op:// value must not be injected")
	_, encPresent := env["ENC_SECRET"]
	assert.False(t, encPresent, "denied enc:// value must not be injected")

	// the literal is not gated and still resolves
	assert.Equal(t, literalSecret, env["LIT_SECRET"], "ungated literal should still pass through")
}

// parseEnv turns `env` output (KEY=VALUE lines) into a map.
func parseEnv(out string) map[string]string {
	env := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		// `binny run` execs the tool under a PTY, which maps \n to \r\n; strip
		// the trailing carriage return so values compare cleanly.
		line = strings.TrimRight(line, "\r")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		env[k] = v
	}
	return env
}
