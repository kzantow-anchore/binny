package authserver

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func parsePrivateKey(pemPrivateKey string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing pkcs#8 private key: %w", err)
	}
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rsaPriv, nil
}

func parsePublicKey(pemPublicKey string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemPublicKey))
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing pkix public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return rsaPub, nil
}
