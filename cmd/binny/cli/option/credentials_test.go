package option

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/binny/internal/authserver"
)

func TestCredentialMatcher_EnvAndDocker(t *testing.T) {
	creds := Credentials{
		"github-readonly": {
			Env: []EnvBinding{{Key: "GH_TOKEN", Token: "op://Vault/GitHubRead/credential"}},
		},
		"github-image-push": {
			Docker: &DockerCredential{
				Username: "op://Vault/GitHubImagePush/username",
				Password: "op://Vault/GitHubImagePush/credential",
			},
		},
	}
	tools := Tools{
		{
			Name: "oras",
			Credentials: map[string]string{
				"ghcr.io/*":      "github-readonly",
				"push ghcr.io/*": "github-image-push",
				"foo bar":        "never-applies",
			},
		},
	}
	m := CredentialMatcher{Tools: tools, Credentials: creds}

	t.Run("push uses only the most-specific match", func(t *testing.T) {
		got := m.GetCredentials([]string{"oras", "push", "ghcr.io/anchore/binny"})
		require.Empty(t, got.Env)
		require.NotNil(t, got.Docker)
		require.Equal(t, "op://Vault/GitHubImagePush/username", got.Docker.Username)
		require.Equal(t, "op://Vault/GitHubImagePush/credential", got.Docker.Password)
	})

	t.Run("pull falls back to broad ghcr.io/* (env only, no docker)", func(t *testing.T) {
		got := m.GetCredentials([]string{"oras", "pull", "ghcr.io/anchore/binny"})
		require.Equal(t, []authserver.EnvBinding{{Key: "GH_TOKEN", Token: "op://Vault/GitHubRead/credential"}}, got.Env)
		require.Nil(t, got.Docker)
	})

	t.Run("no match returns empty CommandCredentials", func(t *testing.T) {
		got := m.GetCredentials([]string{"oras", "pull", "docker.io/library/alpine"})
		require.Empty(t, got.Env)
		require.Nil(t, got.Docker)
	})

	t.Run("unknown tool returns empty CommandCredentials", func(t *testing.T) {
		got := m.GetCredentials([]string{"unknown-tool", "anything"})
		require.Empty(t, got.Env)
		require.Nil(t, got.Docker)
	})

	t.Run("empty command returns empty CommandCredentials", func(t *testing.T) {
		got := m.GetCredentials(nil)
		require.Empty(t, got.Env)
		require.Nil(t, got.Docker)
	})
}

func TestCredentialMatcher_SpecificityOverridesDeclarationOrder(t *testing.T) {
	creds := Credentials{
		"broad":    {Docker: &DockerCredential{Username: "broad-user", Password: "broad-pass"}},
		"specific": {Docker: &DockerCredential{Username: "specific-user", Password: "specific-pass"}},
	}
	tools := Tools{
		{
			Name: "oras",
			Credentials: map[string]string{
				// Map ordering is undefined in Go; the matcher must pick the
				// most-specific pattern regardless of which entry walked first.
				"push ghcr.io/*": "specific",
				"ghcr.io/*":      "broad",
				"*":              "broad",
			},
		},
	}
	m := CredentialMatcher{Tools: tools, Credentials: creds}

	got := m.GetCredentials([]string{"oras", "push", "ghcr.io/anchore/binny"})
	require.NotNil(t, got.Docker)
	require.Equal(t, "specific-user", got.Docker.Username)
	require.Equal(t, "specific-pass", got.Docker.Password)
}

func TestCredentialMatcher_UndefinedCredentialIsSkipped(t *testing.T) {
	tools := Tools{
		{
			Name: "gh",
			Credentials: map[string]string{
				"*": "does-not-exist",
			},
		},
	}
	m := CredentialMatcher{Tools: tools, Credentials: Credentials{}}

	got := m.GetCredentials([]string{"gh", "auth"})
	require.Empty(t, got.Env)
	require.Nil(t, got.Docker)
}

func TestArgsSpecificity(t *testing.T) {
	// Catch-all ("" and "*") < domain glob < specific-verb + domain glob.
	require.Equal(t, argsSpecificity(""), argsSpecificity("*"))
	require.Less(t, argsSpecificity("*"), argsSpecificity("ghcr.io/*"))
	require.Less(t, argsSpecificity("ghcr.io/*"), argsSpecificity("push ghcr.io/*"))
	require.Less(t, argsSpecificity("push ghcr.io/*"), argsSpecificity("push ghcr.io/anchore/*"))
}

func TestMatchArgs(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		args    []string
		want    bool
	}{
		{name: "empty matches anything", pattern: "", args: []string{"anything"}, want: true},
		{name: "star matches anything", pattern: "*", args: []string{"anything"}, want: true},
		{name: "ordered parts across args", pattern: "workflow run", args: []string{"workflow", "run", "--id", "1"}, want: true},
		{name: "ordered parts no match", pattern: "workflow run", args: []string{"pr", "list"}, want: false},
		{name: "leading glob", pattern: "ghcr.io/*", args: []string{"ghcr.io/anchore/something"}, want: true},
		{name: "leading glob mid-args", pattern: "ghcr.io/*", args: []string{"push", "ghcr.io/anchore/something"}, want: true},
		{name: "push prefix glob", pattern: "push ghcr.io/*", args: []string{"push", "ghcr.io/anchore/something"}, want: true},
		{name: "push prefix no match", pattern: "push ghcr.io/*", args: []string{"pull", "ghcr.io/anchore/something"}, want: false},
		{name: "anchored full", pattern: "ghcr.io/anchore/*", args: []string{"ghcr.io/anchore/binny"}, want: true},

		// anchoring: a glob must match a WHOLE arg, so a sibling org/registry
		// sharing a prefix must not match (regression guard for the substring bug).
		{name: "sibling org rejected", pattern: "ghcr.io/anchore/*", args: []string{"ghcr.io/anchore-evil/x"}, want: false},
		{name: "exact org does not match deeper path", pattern: "ghcr.io/anchore", args: []string{"ghcr.io/anchore/binny"}, want: false},
		{name: "registry substring rejected", pattern: "index.docker.io", args: []string{"evil-index.docker.io"}, want: false},
		{name: "suffix after glob still anchored", pattern: "ghcr.io/anchore/*", args: []string{"xghcr.io/anchore/binny"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, MatchArgs(tt.pattern, tt.args))
		})
	}
}
