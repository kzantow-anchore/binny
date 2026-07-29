package option

import (
	"regexp"
	"strings"
)

// Credentials is the top-level `credentials:` map; tools reference entries by name.
type Credentials map[string]Credential

// Credential carries env-var bindings and/or docker login info. Token, Username, and Password hold value-refs: op://…, enc://…, or literal.
type Credential struct {
	Env    []EnvBinding      `json:"env,omitempty" yaml:"env,omitempty" mapstructure:"env"`
	Docker *DockerCredential `json:"docker,omitempty" yaml:"docker,omitempty" mapstructure:"docker"`
}

// EnvBinding is one env-var binding: Key is the var name (case-preserved because it's a YAML value, not a map key that viper would lowercase), Token is the value-ref.
type EnvBinding struct {
	Key   string `json:"key" yaml:"key" mapstructure:"key"`
	Token string `json:"token" yaml:"token" mapstructure:"token"`
}

// DockerCredential is the docker login info; Username and Password are value-refs.
type DockerCredential struct {
	Username string `json:"username,omitempty" yaml:"username,omitempty" mapstructure:"username"`
	Password string `json:"password,omitempty" yaml:"password,omitempty" mapstructure:"password"`
}

var whitespace = regexp.MustCompile(`\s+`)

// MatchArgs reports whether every whitespace-separated part of pattern (each a shell glob) matches a whole arg in order, so "push ghcr.io/*" can span argv boundaries. Parts are anchored (a part must match a full arg, not a substring of one). "" and "*" are equivalent catch-alls.
func MatchArgs(pattern string, args []string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	parts := shellSplit(pattern)
	partIdx := 0
	arg := 0
	for partIdx < len(parts) {
		if arg >= len(args) {
			return false
		}
		partMatch := globToAnchoredRegexp(parts[partIdx])
		if !partMatch.MatchString(args[arg]) {
			arg++
			continue
		}
		// this part matched an arg
		partIdx++
	}
	// not all parts matched
	if partIdx < len(parts) {
		return false
	}
	return true
}

func shellSplit(pattern string) []string {
	// TODO support shell-style quoting
	return whitespace.Split(pattern, -1)
}

// globToAnchoredRegexp converts a shell-style glob into a fully-anchored regexp (^…$; * → .*, ? → ., else escaped), so a part matches a complete arg rather than a substring of one.
func globToAnchoredRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteByte('^')
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteByte('$')
	return regexp.MustCompile(b.String())
}

// argsSpecificity orders patterns least → most specific: "" and "*" are catch-alls, then more literal chars raise the score.
func argsSpecificity(pattern string) int {
	if pattern == "" || pattern == "*" {
		return 0
	}
	literal, wildcards := 0, 0
	for _, r := range pattern {
		if r == '*' || r == '?' {
			wildcards++
		} else {
			literal++
		}
	}
	return literal*100 + wildcards*10
}
