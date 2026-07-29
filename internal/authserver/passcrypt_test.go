package authserver

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptPassword_RoundTrip(t *testing.T) {
	plaintext := []byte("ghp_thisIsATestGitHubPersonalAccessToken_1234567890")

	value, err := EncryptPassword("correct horse battery staple", plaintext)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(value, "enc://"))
	require.NotContains(t, value, string(plaintext), "ciphertext must not leak plaintext")

	pt, err := DecryptPassword("correct horse battery staple", value)
	require.NoError(t, err)
	require.Equal(t, plaintext, pt)
}

func TestDecryptPassword_WrongPassword(t *testing.T) {
	value, err := EncryptPassword("right", []byte("secret"))
	require.NoError(t, err)

	_, err = DecryptPassword("wrong", value)
	require.Error(t, err)
}

func TestEncryptPassword_NonDeterministic(t *testing.T) {
	// A fresh random salt per call means the same value encrypts differently
	// each time, so many values can share one password safely.
	a, err := EncryptPassword("pw", []byte("same"))
	require.NoError(t, err)
	b, err := EncryptPassword("pw", []byte("same"))
	require.NoError(t, err)
	require.NotEqual(t, a, b)
}

func TestEncryptPassword_RequiresPassword(t *testing.T) {
	_, err := EncryptPassword("", []byte("x"))
	require.Error(t, err)

	_, err = DecryptPassword("", "enc://whatever")
	require.Error(t, err)
}

func TestDecryptPassword_RejectsLegacyValue(t *testing.T) {
	// A legacy RSA enc:// value is raw base64 without the v2 version byte; it
	// must be rejected with a clear message rather than a cryptic failure.
	legacy := "enc://" + base64.StdEncoding.EncodeToString([]byte("not-a-v2-blob-marker-here"))
	_, err := DecryptPassword("pw", legacy)
	require.ErrorContains(t, err, "older binny")
}

func TestDecryptPassword_AcceptsValueWithoutPrefix(t *testing.T) {
	value, err := EncryptPassword("pw", []byte("hello"))
	require.NoError(t, err)

	pt, err := DecryptPassword("pw", strings.TrimPrefix(value, "enc://"))
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), pt)
}
