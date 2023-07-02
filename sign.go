package xmldigisign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
)

const (
	Xmlns                     = "http://www.w3.org/2000/09/xmldsig#"
	CanonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	SignatureAlgorithm        = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	DigestMethodAlgorithm     = "http://www.w3.org/2001/04/xmlenc#sha256"
)

var (
	TransformAlgorithms = []string{
		"http://www.w3.org/2000/09/xmldsig#enveloped-signature",
		"http://www.w3.org/2006/12/xml-c14n11",
	}
)

// XML data : Actual xml message in string which needs to be signed
// msgModel : Struct in which your message is going to marshal or un marshal
// Will return signature tag bytes
func (v *xmlSignature) SignXML(xmlData string, msgModel interface{}) (string, error) {
	// Format the XML data
	xmlData, err := formatXML(xmlData, msgModel)
	if err != nil {
		return "", err
	}

	// Canonicalize the XML data
	canonicalXML := CanonicalizeXML(xmlData)

	// Compute the digest of the canonical XML data
	digest := sha256.Sum256([]byte(canonicalXML))

	// Sign the digest using the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, v.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}

	// Encode the signature as base64
	signatureValue := base64.StdEncoding.EncodeToString(signature)

	// Create the Signature struct
	signatureData := Signature{
		Xmlns: Xmlns,
		SignedInfo: SignedInfo{
			CanonicalizationMethod: CanonicalizationMethod{Algorithm: CanonicalizationAlgorithm},
			SignatureMethod:        SignatureMethod{Algorithm: SignatureAlgorithm},
			Reference: Reference{
				Transforms: Transforms{
					Transform: []Transform{
						{Algorithm: TransformAlgorithms[0]},
						{Algorithm: TransformAlgorithms[1]},
					},
				},
				DigestMethod: DigestMethod{Algorithm: DigestMethodAlgorithm},
				DigestValue:  base64.StdEncoding.EncodeToString(digest[:]),
			},
		},
		SignatureValue: signatureValue,
		KeyInfo: KeyInfo{
			X509Data: X509Data{
				X509SubjectName: v.certificate.Subject.String(),
				X509IssuerSerial: X509IssuerSerial{
					X509IssuerName:   v.certificate.Issuer.String(),
					X509SerialNumber: fmt.Sprintf("%v", v.certificate.SerialNumber),
				},
			},
		},
	}

	signatureBytes, err := xml.Marshal(signatureData)
	if err != nil {
		return "", err
	}
	return CanonicalizeXML(string(signatureBytes)), nil
}
