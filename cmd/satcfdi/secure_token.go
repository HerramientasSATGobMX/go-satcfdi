package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/herramientassatgobmx/go-satcfdi/sat"
	"github.com/zalando/go-keyring"
)

const keychainService = "go-satcfdi"
const legacyKeychainService = "satcfdi-go"

var (
	keyringGet    = keyring.Get
	keyringSet    = keyring.Set
	keyringDelete = keyring.Delete
)

type tokenStoreMode string

const (
	tokenStoreDisabled tokenStoreMode = ""
	tokenStoreKeychain tokenStoreMode = "keychain"
)

type tokenStore struct {
	mode  tokenStoreMode
	scope string
}

func newTokenStore(mode string, endpoints sat.Endpoints) (tokenStore, error) {
	normalized := tokenStoreMode(strings.ToLower(strings.TrimSpace(mode)))
	switch normalized {
	case tokenStoreDisabled:
		return tokenStore{}, nil
	case tokenStoreKeychain:
		return tokenStore{
			mode:  normalized,
			scope: tokenScope(endpoints),
		}, nil
	default:
		return tokenStore{}, fmt.Errorf("token-store no soportado: %s", mode)
	}
}

func (s tokenStore) Load(rfc string) (string, error) {
	if s.mode == tokenStoreDisabled {
		return "", fmt.Errorf("token-store deshabilitado; usa -token-store keychain")
	}

	for _, service := range []string{keychainService, legacyKeychainService} {
		token, err := keyringGet(service, tokenKey(s.scope, rfc))
		if err == nil {
			return strings.TrimSpace(token), nil
		}
		if !errors.Is(err, keyring.ErrNotFound) {
			return "", fmt.Errorf("no se pudo leer el token del keychain: %w", err)
		}
	}
	return "", nil
}

func (s tokenStore) Save(rfc, token string) error {
	if s.mode == tokenStoreDisabled {
		return fmt.Errorf("token-store deshabilitado; usa -token-store keychain")
	}
	normalizedRFC := normalizeRFC(rfc)
	normalizedToken := strings.TrimSpace(token)
	if normalizedRFC == "" || normalizedToken == "" {
		return fmt.Errorf("RFC y token son requeridos para guardar el token")
	}
	if err := keyringSet(keychainService, tokenKey(s.scope, normalizedRFC), normalizedToken); err != nil {
		return fmt.Errorf("no se pudo guardar el token en el keychain: %w", err)
	}
	return nil
}

func (s tokenStore) Clear(rfc string) error {
	if s.mode == tokenStoreDisabled {
		return fmt.Errorf("token-store deshabilitado; usa -token-store keychain")
	}

	for _, service := range []string{keychainService, legacyKeychainService} {
		if err := keyringDelete(service, tokenKey(s.scope, rfc)); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("no se pudo eliminar el token del keychain: %w", err)
		}
	}
	return nil
}

func normalizeRFC(rfc string) string {
	return strings.ToUpper(strings.TrimSpace(rfc))
}

func tokenScope(endpoints sat.Endpoints) string {
	payload := strings.Join([]string{
		endpoints.AuthURL,
		endpoints.SolicitaURL,
		endpoints.VerificaURL,
		endpoints.DescargaURL,
	}, "|")
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:8])
}

func tokenKey(scope, rfc string) string {
	return fmt.Sprintf("sat-token:%s:%s", scope, normalizeRFC(rfc))
}
