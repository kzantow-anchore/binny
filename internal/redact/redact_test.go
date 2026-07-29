package redact

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreview(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "one char", in: "a", want: ""},
		{name: "two chars", in: "ab", want: ""},
		{name: "short", in: "abcd", want: "ab••••••••"},
		{name: "medium", in: "one_two_three", want: "on••••••••"},
		{name: "long", in: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx2345", want: "ghp_••••••••2345"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Preview(tt.in)
			require.Equal(t, tt.want, got)

			// For values long enough to have a redactable middle, the middle slice
			// must not appear verbatim in the output.
			if len(tt.in) >= 3 {
				edge := 1
				if len(tt.in) > 8 {
					edge = 4
				}
				middle := tt.in[edge : len(tt.in)-edge]
				if len(middle) > 0 {
					require.False(t, strings.Contains(got, middle),
						"middle of secret should be redacted: got %q contains %q", got, middle)
				}
			}
		})
	}
}
