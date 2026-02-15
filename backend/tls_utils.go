package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	tlsDir      = "/etc/softrouter/tls"
	tlsCertPath = "/etc/softrouter/tls/cert.pem"
	tlsKeyPath  = "/etc/softrouter/tls/key.pem"
)

// ensureTLSCertificates checks for TLS cert/key files and generates self-signed ones if missing.
// Uses ECDSA P-256 for fast key generation and modern security.
// Returns (certPath, keyPath, error).
func ensureTLSCertificates(certFile, keyFile string) (string, string, error) {
	// Use config paths if provided, otherwise defaults
	if certFile == "" {
		certFile = tlsCertPath
	}
	if keyFile == "" {
		keyFile = tlsKeyPath
	}

	// Check if both files exist
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	if certErr == nil && keyErr == nil {
		log.Printf("TLS: Using existing certificates at %s", certFile)
		return certFile, keyFile, nil
	}

	log.Println("TLS: No certificates found. Generating self-signed certificate...")

	// Create directory
	if err := os.MkdirAll(filepath.Dir(certFile), 0700); err != nil {
		return "", "", fmt.Errorf("failed to create TLS directory: %w", err)
	}

	// Generate ECDSA P-256 private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Build Subject Alternative Names
	sans := []net.IP{net.ParseIP("127.0.0.1")}
	dnsNames := []string{"localhost", "router.local", "softrouter.local"}

	// Add the host's IPs
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				sans = append(sans, ipNet.IP)
			}
		}
	}

	// Serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Certificate template — 10 year validity
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SoftRouter"},
			CommonName:   "SoftRouter Web UI",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour), // 1 hour grace for clock skew
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           sans,
		DNSNames:              dnsNames,
	}

	// Self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write cert
	certOut, err := os.OpenFile(certFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return "", "", fmt.Errorf("failed to write cert file: %w", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	// Write key
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", fmt.Errorf("failed to write key file: %w", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	// Log the SANs for user reference
	log.Printf("TLS: Self-signed certificate generated successfully")
	log.Printf("TLS:   Cert: %s", certFile)
	log.Printf("TLS:   Key:  %s", keyFile)
	log.Printf("TLS:   Valid for 10 years")
	log.Printf("TLS:   SANs: %v + %v", dnsNames, sans)

	return certFile, keyFile, nil
}
