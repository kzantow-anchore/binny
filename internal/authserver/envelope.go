package authserver

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// Envelope is the wire format for client→server requests: an RSA-OAEP-wrapped
// AES-256-GCM session key plus the GCM-encrypted payload. All byte fields are
// base64-encoded.
type Envelope struct {
	Key     string `json:"key"`
	Nonce   string `json:"nonce"`
	Payload string `json:"payload"`
}

// SessionResponse is the wire format for server→client responses: the client
// already holds the session key from the originating Envelope, so only the
// fresh nonce and the ciphertext need to travel.
type SessionResponse struct {
	Nonce   string `json:"nonce"`
	Payload string `json:"payload"`
}

const sessionKeyBytes = 32

// gcmNonceLen is the standard AES-GCM nonce size (12 bytes); the enc:// blob
// format relies on this being fixed.
const gcmNonceLen = 12

// SealEnvelope generates a fresh AES-256 session key, GCM-encrypts plaintext
// with it, and wraps the session key with the recipient's RSA public key.
// Returns the envelope and the session key (the caller keeps the session key
// to decrypt the matching SessionResponse).
func SealEnvelope(pubKeyPEM string, plaintext []byte) (Envelope, []byte, error) {
	pub, err := parsePublicKey(pubKeyPEM)
	if err != nil {
		return Envelope{}, nil, err
	}
	sk := make([]byte, sessionKeyBytes)
	if _, err := io.ReadFull(rand.Reader, sk); err != nil {
		return Envelope{}, nil, fmt.Errorf("generating session key: %w", err)
	}
	nonce, ct, err := gcmSeal(sk, plaintext)
	if err != nil {
		return Envelope{}, nil, err
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, sk, nil)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("rsa-oaep wrap session key: %w", err)
	}
	return Envelope{
		Key:     base64.StdEncoding.EncodeToString(wrapped),
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Payload: base64.StdEncoding.EncodeToString(ct),
	}, sk, nil
}

// OpenEnvelope unwraps the session key with privKey and returns the plaintext
// request body plus the session key (so the recipient can encrypt a matching
// response with SealResponse).
func OpenEnvelope(privKeyPEM string, env Envelope) ([]byte, []byte, error) {
	priv, err := parsePrivateKey(privKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := base64.StdEncoding.DecodeString(env.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding session key: %w", err)
	}
	sk, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrapped, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("rsa-oaep unwrap session key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding payload: %w", err)
	}
	pt, err := gcmOpen(sk, nonce, ct)
	if err != nil {
		return nil, nil, err
	}
	return pt, sk, nil
}

// SealResponse encrypts plaintext with an existing session key, returning a
// SessionResponse with a fresh nonce.
func SealResponse(sessionKey, plaintext []byte) (SessionResponse, error) {
	nonce, ct, err := gcmSeal(sessionKey, plaintext)
	if err != nil {
		return SessionResponse{}, err
	}
	return SessionResponse{
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		Payload: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// OpenResponse is the inverse of SealResponse.
func OpenResponse(sessionKey []byte, resp SessionResponse) ([]byte, error) {
	nonce, err := base64.StdEncoding.DecodeString(resp.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decoding nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(resp.Payload)
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}
	return gcmOpen(sessionKey, nonce, ct)
}

func gcmSeal(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, nil, fmt.Errorf("aes-gcm: %w", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generating nonce: %w", err)
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, nil), nil
}

func gcmOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}
	pt, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm open: %w", err)
	}
	return pt, nil
}
