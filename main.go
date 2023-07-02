package xmlDigisign

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

type XMLSignature interface {
	VerifyXMLSignature(string, string, interface{}) error
	SignXML(string, interface{}) (string, error)
}

type xmlSignature struct {
	certificate *x509.Certificate
	privateKey  *rsa.PrivateKey
}

// certFile : path to certficate file
// privateKeyFile : path to private key
func NewXMLSignature(certFile, privateKeyFile string) (XMLSignature, error) {
	// Load the certificate file
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Decode the PEM-encoded certificate
	certificate, err := parseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	// Load the private key file
	privateKeyPEM, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Decode the PEM-encoded private key
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &xmlSignature{
		certificate: certificate,
		privateKey:  privateKey,
	}, nil
}

func CanonicalizeXML(in string) string {
	// Define the replacements to be made in the XML string
	replacements := []struct {
		old, new string
	}{
		{"&#xA;", ""}, // Remove line feed character
		{"&#x9;", ""}, // Remove tab character
		{"> <", "><"}, // Remove whitespace between XML tags
	}

	// Apply the replacements iteratively
	for _, r := range replacements {
		in = strings.ReplaceAll(in, r.old, r.new)
	}

	// Remove leading and trailing whitespaces
	in = strings.TrimSpace(in)

	// Replace consecutive whitespaces with a single space
	in = strings.Join(strings.Fields(in), " ")

	return in
}

func formatXML(in string, msgModel interface{}) (string, error) {
	// Unmarshal XML into the model struct
	if err := xml.Unmarshal([]byte(in), &msgModel); err != nil {
		return "", err
	}

	// Marshal the model struct into XML
	data, err := xml.Marshal(msgModel)
	return string(data), err
}

func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	// Decode the PEM-encoded certificate
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM certificate")
	}
	if len(rest) != 0 {
		return nil, errors.New("unexpected data after PEM certificate")
	}

	// Parse the X.509 certificate
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	return certificate, nil
}

func parsePrivateKey(privateKeyPEM []byte) (*rsa.PrivateKey, error) {
	// Decode the PEM-encoded private key
	block, rest := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM private key")
	}
	if len(rest) != 0 {
		return nil, errors.New("unexpected data after PEM private key")
	}

	// Parse the DER-encoded private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}
