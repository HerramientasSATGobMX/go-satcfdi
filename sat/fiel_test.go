package sat_test

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
)

func TestNewFielEncryptedPKCS8AndMetadata(t *testing.T) {
	fiel := loadFixtureFiel(t, "rsa_key_encrypted_pkcs8.der")

	if got, want := fiel.IssuerName(), "C=MX,ST=Baja California,L=Tijuana,O=HerramientasSATGobMX,OU=Engineering,CN=HerramientasSATGobMX SAT Test"; got != want {
		t.Fatalf("IssuerName() = %q, want %q", got, want)
	}
	if fiel.SerialNumber() == "" {
		t.Fatalf("SerialNumber() should not be empty")
	}
	if _, err := base64.StdEncoding.DecodeString(fiel.CertificateBase64()); err != nil {
		t.Fatalf("CertificateBase64() should be valid base64: %v", err)
	}
	signature, err := fiel.SignSHA1([]byte("herramientas-sat-gob-mx"))
	if err != nil {
		t.Fatalf("SignSHA1() error = %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(signature); err != nil {
		t.Fatalf("SignSHA1() should return base64: %v", err)
	}
}

func TestNewFielIncorrectPassword(t *testing.T) {
	certDER := loadTestFile(t, "certs", "rsa_cert.der")
	keyDER := loadTestFile(t, "certs", "rsa_key_encrypted_pkcs8.der")
	_, err := sat.NewFiel(certDER, keyDER, []byte("wrong-password"))
	if !errors.Is(err, sat.ErrIncorrectPassword) {
		t.Fatalf("expected ErrIncorrectPassword, got %v", err)
	}
}

func TestNewFielSupportsPKCS1Key(t *testing.T) {
	certDER := loadTestFile(t, "certs", "rsa_cert.der")
	keyDER := loadTestFile(t, "certs", "rsa_key_pkcs1.der")
	if _, err := sat.NewFiel(certDER, keyDER, nil); err != nil {
		t.Fatalf("NewFiel() with PKCS#1 key error = %v", err)
	}
}

func TestNewFielInvalidCertificate(t *testing.T) {
	keyDER := loadTestFile(t, "certs", "rsa_key_pkcs1.der")
	_, err := sat.NewFiel([]byte("not-a-cert"), keyDER, nil)
	if !errors.Is(err, sat.ErrInvalidCertificate) {
		t.Fatalf("expected ErrInvalidCertificate, got %v", err)
	}
}
