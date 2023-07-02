package xmldigisign

type (
	Signature struct {
		Xmlns          string     `xml:"xmlns,attr"`
		SignedInfo     SignedInfo `xml:"SignedInfo"`
		SignatureValue string     `xml:"SignatureValue"`
		KeyInfo        KeyInfo    `xml:"KeyInfo"`
	}
	SignedInfo struct {
		CanonicalizationMethod CanonicalizationMethod `xml:"CanonicalizationMethod"`
		SignatureMethod        SignatureMethod        `xml:"SignatureMethod"`
		Reference              Reference              `xml:"Reference"`
	}
	KeyInfo struct {
		X509Data X509Data `xml:"X509Data"`
	}
	CanonicalizationMethod struct {
		Algorithm string `xml:"Algorithm,attr"`
	}
	SignatureMethod struct {
		Algorithm string `xml:"Algorithm,attr"`
	}
	Reference struct {
		URI          string       `xml:"URI,attr"`
		Transforms   Transforms   `xml:"Transforms"`
		DigestMethod DigestMethod `xml:"DigestMethod"`
		DigestValue  string       `xml:"DigestValue"`
	}
	X509Data struct {
		X509SubjectName  string           `xml:"X509SubjectName"`
		X509IssuerSerial X509IssuerSerial `xml:"X509IssuerSerial"`
	}
	Transforms struct {
		Transform []Transform `xml:"Transform"`
	}
	DigestMethod struct {
		Algorithm string `xml:"Algorithm,attr"`
	}
	Transform struct {
		Algorithm string `xml:"Algorithm,attr"`
	}
	X509IssuerSerial struct {
		X509IssuerName   string `xml:"X509IssuerName"`
		X509SerialNumber string `xml:"X509SerialNumber"`
	}
)
