package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRewriteForProgramName(t *testing.T) {
	tests := []struct {
		name        string
		in          []string
		want        []string
		wantWrapped bool
	}{
		{
			name: "plain binny invocation is untouched",
			in:   []string{"/usr/local/bin/binny", "run", "gh"},
			want: []string{"/usr/local/bin/binny", "run", "gh"},
		},
		{
			name: "binny.exe invocation is untouched",
			in:   []string{"binny.exe", "list"},
			want: []string{"binny.exe", "list"},
		},
		{
			name: "docker-credential-binny with action is rewritten",
			in:   []string{"/usr/local/bin/docker-credential-binny", "get"},
			want: []string{"/usr/local/bin/docker-credential-binny", "credential", "docker-helper", "get"},
		},
		{
			name: "docker-credential-binny without action is rewritten verbatim",
			in:   []string{"/usr/local/bin/docker-credential-binny"},
			want: []string{"/usr/local/bin/docker-credential-binny", "credential", "docker-helper"},
		},
		{
			name: "docker-credential-binny basename match (not full path)",
			in:   []string{"docker-credential-binny", "list"},
			want: []string{"docker-credential-binny", "credential", "docker-helper", "list"},
		},
		{
			name:        "other program name is rewritten to run",
			in:          []string{"/usr/local/bin/gh", "auth", "status"},
			want:        []string{"/usr/local/bin/gh", "run", "gh", "auth", "status"},
			wantWrapped: true,
		},
		{
			name:        "other program name without args is rewritten to run",
			in:          []string{"gh"},
			want:        []string{"gh", "run", "gh"},
			wantWrapped: true,
		},
		{
			name:        "other program name with .exe suffix is rewritten to run, stripped",
			in:          []string{"gh.exe", "auth"},
			want:        []string{"gh.exe", "run", "gh", "auth"},
			wantWrapped: true,
		},
		{
			name: "empty argv untouched",
			in:   nil,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, wrapped := rewriteForProgramName(tt.in)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantWrapped, wrapped)
		})
	}
}
