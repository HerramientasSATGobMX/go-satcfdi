package satservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	satcfdiv1 "github.com/herramientassatgobmx/go-satcfdi/proto/satcfdi/v1"
	"github.com/herramientassatgobmx/go-satcfdi/sat"
)

var (
	errInvalidCredentialReference = errors.New("satservice: referencia de credencial inválida")
	errCredentialResolution       = errors.New("satservice: falló la resolución de credenciales")
)

// CredentialMaterial contiene el material DER requerido por sat.NewFiel.
type CredentialMaterial struct {
	CertificateDER     []byte
	PrivateKeyDER      []byte
	PrivateKeyPassword string
}

// CredentialReference identifica una fuente externa de credenciales.
type CredentialReference struct {
	Provider string
	ID       string
}

// CredentialResolver resuelve referencias de credenciales sin empujar la carga
// de secretos a la capa de transporte.
type CredentialResolver interface {
	Resolve(context.Context, CredentialReference) (*CredentialMaterial, error)
	Ready(context.Context) error
}

// FileCredentialResolver resuelve descriptores de credenciales desde una
// ubicación de sistema de archivos permitida. El descriptor es un JSON con los campos
// certificate_path, private_key_path y private_key_password.
type FileCredentialResolver struct {
	allowedDirs []string
}

type fileCredentialDescriptor struct {
	CertificatePath    string `json:"certificate_path"`
	PrivateKeyPath     string `json:"private_key_path"`
	PrivateKeyPassword string `json:"private_key_password"`
}

type credentialCarrier interface {
	GetCredentials() *satcfdiv1.SATCredentials
	GetCredentialRef() *satcfdiv1.CredentialRef
}

// NewFileCredentialResolver construye un resolver de credenciales respaldado en
// sistema de archivos.
func NewFileCredentialResolver(allowedDirs []string) (*FileCredentialResolver, error) {
	canonical := make([]string, 0, len(allowedDirs))
	for _, dir := range allowedDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		path, err := canonicalExistingPath(dir)
		if err != nil {
			return nil, fmt.Errorf("%w: el directorio permitido no está disponible", errCredentialResolution)
		}
		canonical = append(canonical, path)
	}
	if len(canonical) == 0 {
		return nil, fmt.Errorf("%w: se requiere al menos un directorio permitido", errCredentialResolution)
	}
	return &FileCredentialResolver{allowedDirs: canonical}, nil
}

// Ready valida que los directorios permitidos sigan disponibles.
func (r *FileCredentialResolver) Ready(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(r.allowedDirs) == 0 {
		return fmt.Errorf("%w: el resolver no tiene directorios permitidos", errCredentialResolution)
	}
	for _, dir := range r.allowedDirs {
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("%w: el directorio permitido no está disponible", errCredentialResolution)
		}
		if !info.IsDir() {
			return fmt.Errorf("%w: la ruta permitida no es un directorio", errCredentialResolution)
		}
	}
	return nil
}

// Resolve carga un descriptor de credenciales y los archivos DER que
// referencia.
func (r *FileCredentialResolver) Resolve(ctx context.Context, ref CredentialReference) (*CredentialMaterial, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(ref.Provider), "file") {
		return nil, fmt.Errorf("%w: proveedor no soportado", errInvalidCredentialReference)
	}
	if strings.TrimSpace(ref.ID) == "" {
		return nil, fmt.Errorf("%w: id es requerido", errInvalidCredentialReference)
	}

	descriptorPath, err := r.resolveDescriptorPath(ref.ID)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(descriptorPath)
	if err != nil {
		return nil, fmt.Errorf("%w: el descriptor no se puede leer", errCredentialResolution)
	}

	var descriptor fileCredentialDescriptor
	if err := json.Unmarshal(data, &descriptor); err != nil {
		return nil, fmt.Errorf("%w: el JSON del descriptor es inválido", errCredentialResolution)
	}

	certPath, err := r.resolveReferencedPath(filepath.Dir(descriptorPath), descriptor.CertificatePath)
	if err != nil {
		return nil, err
	}
	keyPath, err := r.resolveReferencedPath(filepath.Dir(descriptorPath), descriptor.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	certificateDER, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("%w: el archivo del certificado no se puede leer", errCredentialResolution)
	}
	privateKeyDER, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: el archivo de la llave privada no se puede leer", errCredentialResolution)
	}

	return &CredentialMaterial{
		CertificateDER:     certificateDER,
		PrivateKeyDER:      privateKeyDER,
		PrivateKeyPassword: descriptor.PrivateKeyPassword,
	}, nil
}

func (s *Service) resolveFiel(ctx context.Context, carrier credentialCarrier) (*sat.Fiel, error) {
	inline := carrier.GetCredentials()
	ref := carrier.GetCredentialRef()

	switch {
	case inline == nil && ref == nil:
		return nil, fmt.Errorf("%w: se requiere exactamente uno entre credentials y credential_ref", sat.ErrInvalidRequest)
	case inline != nil && ref != nil:
		return nil, fmt.Errorf("%w: credentials y credential_ref son mutuamente excluyentes", sat.ErrInvalidRequest)
	case inline != nil:
		return sat.NewFiel(
			inline.GetCertificateDer(),
			inline.GetPrivateKeyDer(),
			[]byte(inline.GetPrivateKeyPassword()),
		)
	default:
		if s.resolver == nil {
			return nil, fmt.Errorf("%w: credential_ref no está habilitado en este servidor", errInvalidCredentialReference)
		}
		material, err := s.resolver.Resolve(ctx, credentialReferenceFromProto(ref))
		if err != nil {
			return nil, err
		}
		return sat.NewFiel(
			material.CertificateDER,
			material.PrivateKeyDER,
			[]byte(material.PrivateKeyPassword),
		)
	}
}

func credentialReferenceFromProto(ref *satcfdiv1.CredentialRef) CredentialReference {
	if ref == nil {
		return CredentialReference{}
	}
	return CredentialReference{
		Provider: ref.GetProvider(),
		ID:       ref.GetId(),
	}
}

func (r *FileCredentialResolver) resolveDescriptorPath(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", fmt.Errorf("%w: id es requerido", errInvalidCredentialReference)
	}

	if filepath.IsAbs(id) {
		path, err := canonicalExistingPath(id)
		if err != nil {
			return "", fmt.Errorf("%w: el descriptor no está disponible", errCredentialResolution)
		}
		if !r.isAllowed(path) {
			return "", fmt.Errorf("%w: el descriptor está fuera de los directorios permitidos", errCredentialResolution)
		}
		return path, nil
	}

	for _, dir := range r.allowedDirs {
		candidate, err := canonicalExistingPath(filepath.Join(dir, id))
		if err != nil {
			continue
		}
		if r.isAllowed(candidate) {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%w: no se encontró el descriptor en los directorios permitidos", errCredentialResolution)
}

func (r *FileCredentialResolver) resolveReferencedPath(baseDir, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%w: al descriptor le falta una ruta requerida", errCredentialResolution)
	}

	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}

	canonical, err := canonicalExistingPath(path)
	if err != nil {
		return "", fmt.Errorf("%w: el archivo referenciado no está disponible", errCredentialResolution)
	}
	if !r.isAllowed(canonical) {
		return "", fmt.Errorf("%w: el archivo referenciado está fuera de los directorios permitidos", errCredentialResolution)
	}
	return canonical, nil
}

func (r *FileCredentialResolver) isAllowed(path string) bool {
	for _, allowed := range r.allowedDirs {
		rel, err := filepath.Rel(allowed, path)
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return true
		}
	}
	return false
}

func canonicalExistingPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}
