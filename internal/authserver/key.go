package authserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	pubKeyFileName     = ".key.pub"
	keyBits            = 2048
	serverInfoFileMode = 0o600
	keyDirMode         = 0o700
)

// GenerateKey produces a PEM-encoded RSA 2048 private key (PKCS#8).
func GenerateKey() (string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return "", fmt.Errorf("generating rsa key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("marshaling key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// PublicKeyFromPrivate derives a PEM-encoded PKIX RSA public key from a
// PEM-encoded RSA private key.
func PublicKeyFromPrivate(privKeyPEM string) (string, error) {
	priv, err := parsePrivateKey(privKeyPEM)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshaling public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// LoadPublicKey reads the PEM-encoded public key at path. A missing file
// yields an empty string and no error.
func LoadPublicKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return string(data), nil
}

// SavePublicKey writes the PEM-encoded public key with world-readable perms
// (0644); the public half is not sensitive and clients on the same host need
// to read it to encrypt traffic to the server.
func SavePublicKey(path, pubKeyPEM string) error {
	if err := os.MkdirAll(filepath.Dir(path), keyDirMode); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, serverInfoFileMode)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()
	if err := f.Chmod(serverInfoFileMode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if _, err := f.WriteString(pubKeyPEM); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// GenerateEphemeralKey generates a fresh RSA key pair, publishes the public
// half to pubPath (overwriting any previous file), and returns the private key
// PEM to be held in memory. The private key is deliberately never written to
// disk: the server mints a new pair on every start and clients read the freshly
// published public key.
func GenerateEphemeralKey(pubPath string) (privKeyPEM string, err error) {
	k, err := GenerateKey()
	if err != nil {
		return "", err
	}
	pub, err := PublicKeyFromPrivate(k)
	if err != nil {
		return "", err
	}
	if err := SavePublicKey(pubPath, pub); err != nil {
		return "", err
	}
	return k, nil
}
