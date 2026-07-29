package authserver

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateKey_IsValidPEM(t *testing.T) {
	pemStr, err := GenerateKey()
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block, "expected a PEM block")
	require.Equal(t, "PRIVATE KEY", block.Type)

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	require.NotNil(t, priv)
}

func TestPublicKeyFromPrivate_RoundTrip(t *testing.T) {
	priv, err := GenerateKey()
	require.NoError(t, err)
	pub, err := PublicKeyFromPrivate(priv)
	require.NoError(t, err)

	// Sealing to the derived public key must open with the original private key.
	env, _, err := SealEnvelope(pub, []byte("hunter2"))
	require.NoError(t, err)
	pt, _, err := OpenEnvelope(priv, env)
	require.NoError(t, err)
	require.Equal(t, []byte("hunter2"), pt)
}

func TestGenerateEphemeralKey(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, pubKeyFileName)

	priv, err := GenerateEphemeralKey(pubPath)
	require.NoError(t, err)
	require.NotEmpty(t, priv)

	// Only the public half is written; the private key is never persisted.
	pubData, err := os.ReadFile(pubPath)
	require.NoError(t, err)
	expectedPub, err := PublicKeyFromPrivate(priv)
	require.NoError(t, err)
	require.Equal(t, expectedPub, string(pubData))

	// A second call mints a fresh key and overwrites the published public key.
	priv2, err := GenerateEphemeralKey(pubPath)
	require.NoError(t, err)
	require.NotEqual(t, priv, priv2, "each call should generate a new key")

	pubData2, err := os.ReadFile(pubPath)
	require.NoError(t, err)
	require.NotEqual(t, string(pubData), string(pubData2))
}

func TestSavePublicKey_WorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix file modes not meaningful on windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, pubKeyFileName)

	require.NoError(t, SavePublicKey(path, "pem-bytes"))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(serverInfoFileMode), info.Mode().Perm())
}
