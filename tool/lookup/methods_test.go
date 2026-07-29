package lookup

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsInstallMethod(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		want    bool
	}{
		{
			name:    "valid",
			methods: []string{"lookup", "Lookup", "LOOKUP", "path", "path-lookup", "lookup-path"},
			want:    true,
		},
		{
			name:    "invalid",
			methods: []string{"made up", "github-release", ""},
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, method := range tt.methods {
				t.Run(method, func(t *testing.T) {
					assert.Equal(t, tt.want, IsInstallMethod(method))
					assert.Equal(t, tt.want, IsResolveMethod(method))
				})
			}
		})
	}
}

func TestDefaultVersionResolverConfig(t *testing.T) {
	method, params, err := DefaultVersionResolverConfig(InstallerParameters{
		Name:        "git",
		Path:        "/usr/bin/git",
		SearchPaths: []string{"/opt/bin"},
	})
	assert.NoError(t, err)
	assert.Equal(t, ResolveMethod, method)
	assert.Equal(t, VersionResolutionParameters{
		Name:        "git",
		Path:        "/usr/bin/git",
		SearchPaths: []string{"/opt/bin"},
	}, params)

	method, params, err = DefaultVersionResolverConfig("not a parameters struct")
	assert.NoError(t, err)
	assert.Equal(t, ResolveMethod, method)
	assert.Equal(t, VersionResolutionParameters{}, params)
}
