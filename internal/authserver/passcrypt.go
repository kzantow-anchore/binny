package authserver

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// enc:// at-rest encryption is intentionally independent of the server's
// ephemeral transport key pair: values in config.yaml outlive any server
// process, so they are protected by a user-supplied password rather than a key
// that is regenerated on every start. The password is stretched with argon2id
// and the value is sealed with AES-256-GCM (the same primitive the transport
// envelope uses).

const (
	// encVersion is the leading byte of a v2 (password-based) enc:// blob. It
	// lets us detect and clearly reject legacy RSA-encrypted values, which have
	// no such marker.
	encVersion = 0x02
	encSaltLen = 16

	// argon2id parameters (RFC 9106 second-recommended option: t=3, 64 MiB, 4 lanes).
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

// EncryptPassword derives a key from password via argon2id and seals plaintext
// with AES-256-GCM, returning an "enc://<base64>" value suitable for pasting
// into config.yaml. Each call uses a fresh random salt, so the same password
// can protect many values safely.
func EncryptPassword(password string, plaintext []byte) (string, error) {
	if password == "" {
		return "", errors.New("password is required")
	}
	salt := make([]byte, encSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	nonce, ct, err := gcmSeal(key, plaintext)
	if err != nil {
		return "", err
	}
	blob := make([]byte, 0, 1+len(salt)+len(nonce)+len(ct))
	blob = append(blob, encVersion)
	blob = append(blob, salt...)
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	return encPrefix + base64.StdEncoding.EncodeToString(blob), nil
}

// DecryptPassword is the inverse of EncryptPassword. It accepts a value with or
// without the leading "enc://" prefix. A wrong password surfaces as a GCM
// authentication failure.
func DecryptPassword(password, value string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("no credential password provided")
	}
	b64 := strings.TrimPrefix(value, encPrefix)
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("enc:// value is not valid base64: %w", err)
	}
	if len(blob) == 0 || blob[0] != encVersion {
		return nil, errors.New("enc:// value was produced by an older binny; re-run `binny credential encrypt`")
	}
	rest := blob[1:]
	if len(rest) < encSaltLen+gcmNonceLen {
		return nil, errors.New("enc:// value is malformed")
	}
	salt := rest[:encSaltLen]
	nonce := rest[encSaltLen : encSaltLen+gcmNonceLen]
	ct := rest[encSaltLen+gcmNonceLen:]
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	plain, err := gcmOpen(key, nonce, ct)
	if err != nil {
		return nil, fmt.Errorf("decrypting enc:// value (wrong password?): %w", err)
	}
	return plain, nil
}
