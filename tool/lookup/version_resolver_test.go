package lookup

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/binny"
)

func TestVersionResolver_ResolveVersion(t *testing.T) {
	tests := []struct {
		name      string
		config    VersionResolutionParameters
		intent    binny.VersionIntent
		runOutput string
		runErr    error
		want      string
		wantErr   assert.ErrorAssertionFunc
	}{
		{
			name:      "default args, default pattern",
			config:    VersionResolutionParameters{Name: "git"},
			intent:    binny.VersionIntent{Want: "current"},
			runOutput: "git version 2.42.1",
			want:      "2.42.1",
			wantErr:   assert.NoError,
		},
		{
			name:      "extracts leading v",
			config:    VersionResolutionParameters{Name: "binny"},
			intent:    binny.VersionIntent{Want: ""},
			runOutput: "binny v0.13.0",
			want:      "v0.13.0",
			wantErr:   assert.NoError,
		},
		{
			name:      "honors specific version",
			config:    VersionResolutionParameters{Name: "git"},
			intent:    binny.VersionIntent{Want: "2.0.0"},
			runOutput: "should not be used",
			want:      "2.0.0",
			wantErr:   assert.NoError,
		},
		{
			name:      "treats latest like current",
			config:    VersionResolutionParameters{Name: "git"},
			intent:    binny.VersionIntent{Want: "latest"},
			runOutput: "git version 2.42.1",
			want:      "2.42.1",
			wantErr:   assert.NoError,
		},
		{
			name: "custom pattern with capture group",
			config: VersionResolutionParameters{
				Name:    "docker",
				Args:    []string{"version", "--format", "{{.Client.Version}}"},
				Pattern: `Docker (.+)`,
			},
			intent:    binny.VersionIntent{Want: "current"},
			runOutput: "Docker 24.0.5-rc1",
			want:      "24.0.5-rc1",
			wantErr:   assert.NoError,
		},
		{
			name:      "no match",
			config:    VersionResolutionParameters{Name: "weird"},
			intent:    binny.VersionIntent{Want: "current"},
			runOutput: "no version here",
			wantErr:   assert.Error,
		},
		{
			name:    "command fails",
			config:  VersionResolutionParameters{Name: "broken"},
			intent:  binny.VersionIntent{Want: "current"},
			runErr:  fmt.Errorf("boom"),
			wantErr: assert.Error,
		},
		{
			name:    "missing name",
			config:  VersionResolutionParameters{},
			intent:  binny.VersionIntent{Want: "current"},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVersionResolver(tt.config)
			v.lookupPath = func(name string) (string, error) {
				return "/usr/bin/" + name, nil
			}
			v.runner = func(_ context.Context, _ string, _ []string) (string, error) {
				return tt.runOutput, tt.runErr
			}
			got, err := v.ResolveVersion(context.Background(), tt.intent)
			if !tt.wantErr(t, err) {
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVersionResolver_LookupFails(t *testing.T) {
	v := NewVersionResolver(VersionResolutionParameters{Name: "missing"})
	v.lookupPath = func(_ string) (string, error) {
		return "", fmt.Errorf("not found")
	}

	_, err := v.ResolveVersion(context.Background(), binny.VersionIntent{Want: "current"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		pattern string
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "default pattern extracts semver",
			output:  "tool version 1.2.3",
			want:    "1.2.3",
			wantErr: assert.NoError,
		},
		{
			name:    "default pattern extracts v-prefixed",
			output:  "tool v1.2.3",
			want:    "v1.2.3",
			wantErr: assert.NoError,
		},
		{
			name:    "default pattern handles short version",
			output:  "tool 1.2",
			want:    "1.2",
			wantErr: assert.NoError,
		},
		{
			name:    "default pattern with prerelease",
			output:  "tool 1.2.3-beta.1",
			want:    "1.2.3-beta.1",
			wantErr: assert.NoError,
		},
		{
			name:    "custom pattern with capture",
			output:  "Build: ABC123",
			pattern: `Build: (\S+)`,
			want:    "ABC123",
			wantErr: assert.NoError,
		},
		{
			name:    "invalid pattern",
			output:  "foo",
			pattern: `[`,
			wantErr: assert.Error,
		},
		{
			name:    "empty output",
			output:  "",
			wantErr: assert.Error,
		},
		{
			name:    "no match",
			output:  "no numbers at all",
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractVersion(tt.output, tt.pattern)
			if !tt.wantErr(t, err) {
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
