package authserver

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSealEnvelope_OpenEnvelope_RoundTrip(t *testing.T) {
	priv, err := GenerateKey()
	require.NoError(t, err)
	pub, err := PublicKeyFromPrivate(priv)
	require.NoError(t, err)

	plaintext := []byte(`{"scope":"github","command":["binny","run","gh"]}`)
	env, sk, err := SealEnvelope(pub, plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, env.Key)
	require.NotEmpty(t, env.Nonce)
	require.NotEmpty(t, env.Payload)
	require.NotContains(t, env.Payload, "scope")
	require.Len(t, sk, sessionKeyBytes)

	got, sk2, err := OpenEnvelope(priv, env)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
	require.Equal(t, sk, sk2, "server must recover the same session key the client generated")
}

func TestSealResponse_OpenResponse_RoundTrip(t *testing.T) {
	priv, err := GenerateKey()
	require.NoError(t, err)
	pub, err := PublicKeyFromPrivate(priv)
	require.NoError(t, err)

	_, sk, err := SealEnvelope(pub, []byte("hello"))
	require.NoError(t, err)

	body := []byte(`{"value":"ghp_secret"}`)
	resp, err := SealResponse(sk, body)
	require.NoError(t, err)
	require.NotEmpty(t, resp.Nonce)
	require.NotEmpty(t, resp.Payload)
	require.NotContains(t, resp.Payload, "ghp_secret")

	got, err := OpenResponse(sk, resp)
	require.NoError(t, err)
	require.Equal(t, body, got)
}

func TestSealEnvelope_FreshSessionKeyPerCall(t *testing.T) {
	priv, err := GenerateKey()
	require.NoError(t, err)
	pub, err := PublicKeyFromPrivate(priv)
	require.NoError(t, err)

	_, sk1, err := SealEnvelope(pub, []byte("a"))
	require.NoError(t, err)
	_, sk2, err := SealEnvelope(pub, []byte("a"))
	require.NoError(t, err)
	require.NotEqual(t, sk1, sk2, "session keys must be random per call")
}

func TestOpenEnvelope_WrongPrivateKeyFails(t *testing.T) {
	pubKeyPriv, err := GenerateKey()
	require.NoError(t, err)
	pub, err := PublicKeyFromPrivate(pubKeyPriv)
	require.NoError(t, err)

	env, _, err := SealEnvelope(pub, []byte("secret"))
	require.NoError(t, err)

	otherPriv, err := GenerateKey()
	require.NoError(t, err)
	_, _, err = OpenEnvelope(otherPriv, env)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "unwrap") || strings.Contains(err.Error(), "decrypt"))
}

func TestOpenResponse_TamperedPayloadFails(t *testing.T) {
	priv, err := GenerateKey()
	require.NoError(t, err)
	pub, err := PublicKeyFromPrivate(priv)
	require.NoError(t, err)

	_, sk, err := SealEnvelope(pub, []byte("x"))
	require.NoError(t, err)
	resp, err := SealResponse(sk, []byte("hello"))
	require.NoError(t, err)

	// Flip the first base64 char to one guaranteed different from the original
	// (else, ~1/64 of the time, "A" would match and the tamper would be a no-op).
	flip := byte('A')
	if resp.Payload[0] == flip {
		flip = 'B'
	}
	tampered := resp
	tampered.Payload = string(flip) + resp.Payload[1:]
	_, err = OpenResponse(sk, tampered)
	require.Error(t, err, "GCM tag must reject tampered ciphertext")
}
