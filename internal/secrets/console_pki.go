package secrets

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/securefs"
)

const (
	ConsoleProxyCAFile         = "console_proxy_ca.txt"
	ConsoleProxyServerCertFile = "console_proxy_server_cert.txt"
	ConsoleProxyServerKeyFile  = "console_proxy_server_key.txt"
	ConsoleProxyClientCertFile = "console_proxy_client_cert.txt"
	ConsoleProxyClientKeyFile  = "console_proxy_client_key.txt"

	ConsoleProxyServerName = "sdbx-console.internal"
	ConsoleProxyClientName = "sdbx-traefik"
)

var consoleProxyFiles = []string{
	ConsoleProxyCAFile,
	ConsoleProxyServerCertFile,
	ConsoleProxyServerKeyFile,
	ConsoleProxyClientCertFile,
	ConsoleProxyClientKeyFile,
}

// IsConsoleProxySecret reports whether a catalog secret is generated as part
// of the internal proxy trust set rather than supplied by an operator.
func IsConsoleProxySecret(name string) bool {
	switch strings.TrimSuffix(name, ".txt") {
	case "console_proxy_ca", "console_proxy_server_cert", "console_proxy_server_key",
		"console_proxy_client_cert", "console_proxy_client_key":
		return true
	default:
		return false
	}
}

// ValidateConsoleProxyPKI verifies the complete trust set without modifying it.
func ValidateConsoleProxyPKI(secretsDir string) error {
	contents := make(map[string][]byte, len(consoleProxyFiles))
	defer func() {
		for _, data := range contents {
			wipeSecretBytes(data)
		}
	}()
	for _, name := range consoleProxyFiles {
		data, err := securefs.ReadRegularFileAt(secretsDir, name, maxSecretFileSize)
		if err != nil {
			return fmt.Errorf("read console proxy PKI %s: %w", name, err)
		}
		contents[name] = data
	}
	return validateConsoleProxyPKI(contents, time.Now())
}

// EnsureConsoleProxyPKI creates the private CA and leaf certificates used only
// by Traefik and the host management console. Existing valid material is never
// rotated implicitly. A partial or invalid PKI fails closed so an operator can
// recover the matching files from backup instead of silently losing access.
func EnsureConsoleProxyPKI(secretsDir string) error {
	contents := make(map[string][]byte, len(consoleProxyFiles))
	empty := 0
	for _, name := range consoleProxyFiles {
		data, err := securefs.ReadRegularFileAt(secretsDir, name, maxSecretFileSize)
		if err != nil {
			return fmt.Errorf("read console proxy PKI %s: %w", name, err)
		}
		contents[name] = data
		if len(strings.TrimSpace(string(data))) == 0 {
			empty++
		}
	}
	defer func() {
		for _, data := range contents {
			wipeSecretBytes(data)
		}
	}()

	if empty == 0 {
		return validateConsoleProxyPKI(contents, time.Now())
	}
	if empty != len(consoleProxyFiles) {
		return fmt.Errorf("console proxy PKI is incomplete; restore the matching certificate set")
	}

	generated, err := generateConsoleProxyPKI(time.Now())
	if err != nil {
		return err
	}
	defer func() {
		for _, data := range generated {
			wipeSecretBytes(data)
		}
	}()
	for _, name := range consoleProxyFiles {
		if err := securefs.WriteFileAtomic(
			filepath.Join(secretsDir, name),
			generated[name],
			0o700,
			0o600,
		); err != nil {
			return fmt.Errorf("write console proxy PKI %s: %w", name, err)
		}
	}
	return nil
}

func generateConsoleProxyPKI(now time.Time) (map[string][]byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate console proxy CA key: %w", err)
	}
	caSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "SDBX console proxy CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create console proxy CA: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated console proxy CA: %w", err)
	}

	serverCert, serverKey, err := createConsoleLeaf(
		caCert,
		caKey,
		ConsoleProxyServerName,
		x509.ExtKeyUsageServerAuth,
		now,
	)
	if err != nil {
		return nil, err
	}
	clientCert, clientKey, err := createConsoleLeaf(
		caCert,
		caKey,
		ConsoleProxyClientName,
		x509.ExtKeyUsageClientAuth,
		now,
	)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		ConsoleProxyCAFile:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		ConsoleProxyServerCertFile: serverCert,
		ConsoleProxyServerKeyFile:  serverKey,
		ConsoleProxyClientCertFile: clientCert,
		ConsoleProxyClientKeyFile:  clientKey,
	}, nil
}

func createConsoleLeaf(
	ca *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	name string,
	usage x509.ExtKeyUsage,
	now time.Time,
) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate console proxy leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create console proxy leaf certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal console proxy leaf key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate console proxy certificate serial: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func validateConsoleProxyPKI(contents map[string][]byte, now time.Time) error {
	ca, err := parseCertificate(contents[ConsoleProxyCAFile])
	if err != nil || !ca.IsCA {
		return fmt.Errorf("console proxy CA is invalid")
	}
	if now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return fmt.Errorf("console proxy CA is outside its validity period")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	checks := []struct {
		certFile string
		keyFile  string
		name     string
		usage    x509.ExtKeyUsage
	}{
		{ConsoleProxyServerCertFile, ConsoleProxyServerKeyFile, ConsoleProxyServerName, x509.ExtKeyUsageServerAuth},
		{ConsoleProxyClientCertFile, ConsoleProxyClientKeyFile, ConsoleProxyClientName, x509.ExtKeyUsageClientAuth},
	}
	for _, check := range checks {
		pair, pairErr := tls.X509KeyPair(contents[check.certFile], contents[check.keyFile])
		if pairErr != nil || len(pair.Certificate) != 1 {
			return fmt.Errorf("console proxy certificate pair %s is invalid", check.name)
		}
		cert, parseErr := x509.ParseCertificate(pair.Certificate[0])
		if parseErr != nil {
			return fmt.Errorf("parse console proxy certificate %s: %w", check.name, parseErr)
		}
		if _, verifyErr := cert.Verify(x509.VerifyOptions{
			DNSName:     check.name,
			Roots:       pool,
			KeyUsages:   []x509.ExtKeyUsage{check.usage},
			CurrentTime: now,
		}); verifyErr != nil {
			return fmt.Errorf("verify console proxy certificate %s: %w", check.name, verifyErr)
		}
	}
	return nil
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("expected one PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ProvisionConsoleRuntime copies the server-side trust material and canonical
// public hostname into root-owned runtime files readable by the sdbx group.
func ProvisionConsoleRuntime(secretsDir, runtimeDir, publicHost string, gid int) error {
	if gid < 0 || strings.TrimSpace(publicHost) == "" {
		return fmt.Errorf("valid console runtime ownership and public hostname are required")
	}
	if err := EnsureConsoleProxyPKI(secretsDir); err != nil {
		return err
	}
	files := map[string]string{
		ConsoleProxyCAFile:         "console-proxy-ca.pem",
		ConsoleProxyServerCertFile: "console-proxy-server.pem",
		ConsoleProxyServerKeyFile:  "console-proxy-server-key.pem",
	}
	for source, target := range files {
		data, err := securefs.ReadRegularFileAt(secretsDir, source, maxSecretFileSize)
		if err != nil {
			return fmt.Errorf("read console runtime source %s: %w", source, err)
		}
		mode := os.FileMode(0o640)
		if err := securefs.WriteFileAtomic(filepath.Join(runtimeDir, target), data, 0o750, mode); err != nil {
			wipeSecretBytes(data)
			return fmt.Errorf("write console runtime file %s: %w", target, err)
		}
		wipeSecretBytes(data)
		if err := os.Chown(filepath.Join(runtimeDir, target), 0, gid); err != nil {
			return fmt.Errorf("set console runtime ownership for %s: %w", target, err)
		}
	}
	hostPath := filepath.Join(runtimeDir, "console-public-host")
	if err := securefs.WriteFileAtomic(hostPath, []byte(strings.TrimSpace(publicHost)+"\n"), 0o750, 0o640); err != nil {
		return fmt.Errorf("write console public hostname: %w", err)
	}
	if err := os.Chown(hostPath, 0, gid); err != nil {
		return fmt.Errorf("set console public hostname ownership: %w", err)
	}
	return nil
}
