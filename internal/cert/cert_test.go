package cert

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("certPEM is empty")
	}
	if len(keyPEM) == 0 {
		t.Error("keyPEM is empty")
	}

	// Verify cert can be parsed
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Errorf("failed to create X509 key pair: %v", err)
	}
}

func TestLoadCA(t *testing.T) {
	// Generate CA
	certPEM, keyPEM, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Write to temp files
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	// Load and verify
	cert, key, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	if cert == nil {
		t.Fatal("cert is nil")
		return
	}
	if key == nil {
		t.Fatal("key is nil")
	}

	// Verify it's a CA cert
	if !cert.IsCA {
		t.Error("loaded cert is not a CA")
	}
	if cert.Subject.CommonName != "test-ca" {
		t.Errorf("wrong common name: got %q, want %q", cert.Subject.CommonName, "test-ca")
	}
}

func TestLoadCA_NotFound(t *testing.T) {
	_, _, err := LoadCA("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for nonexistent files")
	}
}

func TestSignHostCert(t *testing.T) {
	// Generate CA
	certPEM, keyPEM, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Write to temp files and load
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	caCert, caKey, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	// Sign a host certificate
	hostCert, err := SignHostCert("example.com", caCert, caKey)
	if err != nil {
		t.Fatalf("SignHostCert failed: %v", err)
	}

	if hostCert == nil {
		t.Fatal("hostCert is nil")
		return
	}
	if hostCert.Leaf == nil {
		t.Fatal("hostCert.Leaf is nil")
	}

	// Verify the host certificate
	if hostCert.Leaf.Subject.CommonName != "example.com" {
		t.Errorf("wrong common name: got %q, want %q", hostCert.Leaf.Subject.CommonName, "example.com")
	}
	if len(hostCert.Leaf.DNSNames) != 1 || hostCert.Leaf.DNSNames[0] != "example.com" {
		t.Errorf("wrong DNS names: %v", hostCert.Leaf.DNSNames)
	}

	// Verify it's signed by the CA
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := hostCert.Leaf.Verify(opts); err != nil {
		t.Errorf("host cert verification failed: %v", err)
	}
}

func TestSignHostCert_MultipleHosts(t *testing.T) {
	// Generate CA
	certPEM, keyPEM, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// Write to temp files and load
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-cert.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	caCert, caKey, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}

	// Sign multiple host certificates
	hosts := []string{"github.com", "api.github.com", "anthropic.com"}
	for _, host := range hosts {
		hostCert, err := SignHostCert(host, caCert, caKey)
		if err != nil {
			t.Errorf("SignHostCert(%q) failed: %v", host, err)
			continue
		}

		if hostCert.Leaf.Subject.CommonName != host {
			t.Errorf("wrong common name: got %q, want %q", hostCert.Leaf.Subject.CommonName, host)
		}
	}
}
