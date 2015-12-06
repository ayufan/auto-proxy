package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/Sirupsen/logrus"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"time"
)

type Certificate struct {
	TLS             *tls.Certificate
	X509            *x509.Certificate
	UpdateTime      time.Time
	Requesting      bool
	Name            string
	CertificateFile string
	KeyFile         string
}

var defaultCertificate *Certificate

func NewCertificate(serverName string) *Certificate {
	return &Certificate{
		Name:            serverName,
		CertificateFile: filepath.Join(*certsDirectory, serverName+".crt"),
		KeyFile:         filepath.Join(*certsDirectory, serverName+".key"),
	}
}

type CertificateChallenge interface {
	AddCertificate(name string, certificate *tls.Certificate)
	RemoveCertificate(name string)
	AddHttpUri(uriPath, resource string)
	RemoveHttpUri(uriPath string)
}

func (c *Certificate) log() *logrus.Entry {
	return logrus.WithField("name", c.Name)
}

func (c *Certificate) getX509() (*x509.Certificate, error) {
	if c.X509 != nil {
		return c.X509, nil
	} else if c.TLS == nil || len(c.TLS.Certificate) == 0 || len(c.TLS.Certificate[0]) == 0 {
		return nil, errors.New("Missing TLS certificate")
	}
	x509Cert, err := x509.ParseCertificate(c.TLS.Certificate[0])
	if err != nil {
		return nil, err
	}
	c.X509 = x509Cert
	return x509Cert, nil
}

func (c *Certificate) IsExpiring(duration time.Duration) bool {
	x509 := c.X509
	if x509 != nil {
		return false
	}
	if x509.NotAfter.Sub(time.Now()) < duration {
		return true
	}
	return false
}

func (c *Certificate) Matches(serverName string) bool {
	if c.Name == serverName {
		return true
	}
	return false
}

func (c *Certificate) Load() error {
	c.log().WithField("certificate", c.CertificateFile).WithField("key", c.KeyFile).Debugln("Loading X509KeyPair...")
	tls, err := tls.LoadX509KeyPair(c.CertificateFile, c.KeyFile)
	if err != nil {
		return err
	}

	x509Cert, err := x509.ParseCertificate(tls.Certificate[0])
	if err != nil {
		return err
	}

	c.TLS = &tls
	c.X509 = x509Cert
	return nil
}

func (c *Certificate) generateKey() (*rsa.PrivateKey, error) {
	if *useDefaultKey && defaultCertificate != nil && defaultCertificate.TLS != nil && defaultCertificate.TLS.PrivateKey != nil {
		return defaultCertificate.TLS.PrivateKey.(*rsa.PrivateKey), nil
	}

	return rsa.GenerateKey(rand.Reader, 2048)
}

func (c *Certificate) createCertificateRequest() (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	certKey, err := c.generateKey()
	if err != nil {
		return nil, nil, err
	}

	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &certKey.PublicKey,
		Subject:            pkix.Name{CommonName: c.Name},
		DNSNames:           []string{c.Name},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, certKey)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}
	return csr, certKey, nil
}

func (c *Certificate) CreateSelfSigned() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             &key.PublicKey,
		Subject:               pkix.Name{CommonName: c.Name},
		DNSNames:              []string{c.Name},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}

	return c.finish(cert, key)
}

func (c *Certificate) CanUpdate(duration time.Duration) bool {
	return !c.Requesting && time.Since(c.UpdateTime) > duration
}

func (c *Certificate) finish(cert *x509.Certificate, key *rsa.PrivateKey) error {
	// Create TLS certificate
	c.TLS = &tls.Certificate{
		Certificate: [][]byte{
			cert.Raw,
		},
		PrivateKey: key,
	}
	c.X509 = cert

	// Write certificates to file
	err := ioutil.WriteFile(c.CertificateFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}), 0600)
	if err != nil {
		logrus.WithField("name", c.Name).WithField("file", c.CertificateFile).WithError(err).Warningln("Failed to write certificate")
		return err
	}

	// Write private key to file
	err = ioutil.WriteFile(c.KeyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), 0600)
	if err != nil {
		logrus.WithField("name", c.Name).WithField("file", c.CertificateFile).WithError(err).Warningln("Failed to write private key:")
		return err
	}

	return nil
}

func (c *Certificate) Request(certificateChallenge CertificateChallenge) error {
	if certificateChallenge == nil {
		return errors.New("missing certificate challenge handler")
	}

	c.UpdateTime = time.Now()
	le := &LetsEncrypt{}
	c.log().Infoln("Requesting a new certificate...")

	uriPath, resource, challenge, err := le.requestHttp(c.Name)
	if err != nil {
		return err
	}

	certificateChallenge.AddHttpUri(uriPath, resource)
	defer certificateChallenge.RemoveHttpUri(uriPath)

	c.log().Debugln("Finishing certificate request challenge...")
	err = le.finishChallenge(challenge)
	if err != nil {
		return err
	}

	c.log().Debugln("Creating ceritifcate request...")
	csr, key, err := c.createCertificateRequest()
	if err != nil {
		return err
	}

	c.log().Debugln("Creating a certificate...")
	certificate, err := le.createCertificate(csr)
	if err != nil {
		return err
	}

	c.log().Infoln("Generated a new certificate.")
	return c.finish(certificate, key)
}
