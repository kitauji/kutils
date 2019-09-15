package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
	"errors"
	"github.com/lithammer/shortuuid"
)

var (
	caTLSCert *tls.Certificate
	caX509Cert *x509.Certificate
)

// LoadCA loads certificate and private key PEM files to sign 
// a generated certificate.
func LoadCA(caCertFile, caKeyFile string) error {
	tlsCert, err := tls.LoadX509KeyPair(caCertFile, caKeyFile)
	if err != nil {
		return err
	}
	caTLSCert = &tlsCert

	
	x509Cert, err := x509.ParseCertificate(caTLSCert.Certificate[0])
	if err != nil {
		return err
	}

	caX509Cert = x509Cert
	return nil
}

func CreateCertificate(hosts []string, validDays int) (*tls.Certificate, error) {
	if len(hosts) == 0 {
		return nil, errors.New("No host name")
	}

	// Generate a keypair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	publicKey := &privateKey.PublicKey

	// Prepare a template to create a certificate
	serialNum := time.Now().Unix()
	
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serialNum),
		Subject:      pkix.Name{CommonName: hosts[0]},
		SubjectKeyId: []byte(shortuuid.New()),
		DNSNames:     hosts, // Subject Alternate Name
		BasicConstraintsValid: true,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, validDays),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment,
	}

	// Create and sign a certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, caX509Cert, publicKey, caTLSCert.PrivateKey)
	if err != nil {
		return nil, err
	}

	certPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", 
		Bytes: certDER,
	})
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", 
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	tlsCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}

