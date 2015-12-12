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

const intermediateCerts = `
-----BEGIN CERTIFICATE-----
MIIEqDCCA5CgAwIBAgIRAJgT9HUT5XULQ+dDHpceRL0wDQYJKoZIhvcNAQELBQAw
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzAeFw0xNTEwMTkyMjMzMzZaFw0yMDEwMTkyMjMzMzZa
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAJzTDPBa5S5Ht3JdN4OzaGMw6tc1Jhkl4b2+NfFwki+3uEtB
BaupnjUIWOyxKsRohwuj43Xk5vOnYnG6eYFgH9eRmp/z0HhncchpDpWRz/7mmelg
PEjMfspNdxIknUcbWuu57B43ABycrHunBerOSuu9QeU2mLnL/W08lmjfIypCkAyG
dGfIf6WauFJhFBM/ZemCh8vb+g5W9oaJ84U/l4avsNwa72sNlRZ9xCugZbKZBDZ1
gGusSvMbkEl4L6KWTyogJSkExnTA0DHNjzE4lRa6qDO4Q/GxH8Mwf6J5MRM9LTb4
4/zyM2q5OTHFr8SNDR1kFjOq+oQpttQLwNh9w5MCAwEAAaOCAZIwggGOMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMH8GCCsGAQUFBwEBBHMwcTAy
BggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3RpZC5vY3NwLmlkZW50cnVzdC5j
b20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlkZW50cnVzdC5jb20vcm9vdHMv
ZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFMSnsaR7LHH62+FLkHX/xBVghYkQ
MFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQBgt8TAQEBMDAwLgYIKwYBBQUH
AgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcwPAYDVR0fBDUw
MzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3QuY29tL0RTVFJPT1RDQVgzQ1JM
LmNybDATBgNVHR4EDDAKoQgwBoIELm1pbDAdBgNVHQ4EFgQUqEpqYwR93brm0Tm3
pkVl7/Oo7KEwDQYJKoZIhvcNAQELBQADggEBANHIIkus7+MJiZZQsY14cCoBG1hd
v0J20/FyWo5ppnfjL78S2k4s2GLRJ7iD9ZDKErndvbNFGcsW+9kKK/TnY21hp4Dd
ITv8S9ZYQ7oaoqs7HwhEMY9sibED4aXw09xrJZTC9zK1uIfW6t5dHQjuOWv+HHoW
ZnupyxpsEUlEaFb+/SCI4KCSBdAsYxAcsHYI5xxEI4LutHp6s3OT2FuO90WfdsIk
6q78OMSdn875bNjdBYAqxUp2/LEIHfDBkLoQz0hFJmwAbYahqKaLn73PAAm1X2kj
f1w8DdnkabOLGeOVcj9LQ+s67vBykx4anTjURkbqZslUEUsn2k5xeua2zUk=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEqDCCA5CgAwIBAgIRAMODTJjAvWslLKN5tm+lKw4wDQYJKoZIhvcNAQELBQAw
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzAeFw0xNTEwMTkyMjM1MDFaFw0yMDEwMTkyMjM1MDFa
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMjCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAOEkdEJ7t5Ex2XP/OKrYzkRctzkK3ESuDb1FuZc3Z6+9UE9f
0xBUa/dB2o5j5m1bwOhAqYxB/NEDif9iYQlg1gcFeJqQvRpkPk/cz3cviWvLZ69B
TcWNAMBr/o2E3LXylTGo6PaQoENKk3Rcsz5DaUuJIkd0UT6ZZMPNJAH5hC8odxci
p93DbAhMZi83dMVvk46wRjcWYdFQmMiwD09YU3ys9totlmFQrUPcCqZPnrVSuZyO
707fRrMx3CD8acKjIHU+7DgbNk5mZtLf9Wakky97pg6UPmA9Skscb7q0TRw8kVhu
L03E2nDb7QE5dsBJ5+k1tRQGkMHlkuIQ/Wu5tIUCAwEAAaOCAZIwggGOMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMH8GCCsGAQUFBwEBBHMwcTAy
BggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3RpZC5vY3NwLmlkZW50cnVzdC5j
b20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlkZW50cnVzdC5jb20vcm9vdHMv
ZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFMSnsaR7LHH62+FLkHX/xBVghYkQ
MFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQBgt8TAQEBMDAwLgYIKwYBBQUH
AgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcwPAYDVR0fBDUw
MzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3QuY29tL0RTVFJPT1RDQVgzQ1JM
LmNybDATBgNVHR4EDDAKoQgwBoIELm1pbDAdBgNVHQ4EFgQUxbGrTkyxzWQwk37B
hJkFq+YD4iUwDQYJKoZIhvcNAQELBQADggEBAAcSAhaE7rvHxyUnhgkEpMR56o2I
IH+mlw5kknjhAuvaBIAM59MZkFbFg5CrNWt8K+G3UoxJgFwv7HvJJxqwgPpNgXC/
uT3prkvwt+2lvzKJKbqdH+lo40P8EuSyyJOz2hjrRzNMHbJHYDS9OhF5WC5LOQQa
ydgLZ/JHxXgJypEZqcmVgQ+yYBs0XPwXjE7OE8vbx5REwu7gToMIqAoWRoWW2MxS
g28RGPVnHzHk2XV1nZGy9T+NYQ91vWWJr1pzNEFZ0cnA2xGwTeJ+zZ3URCfw3Z1U
+YAL3YUmrvdoRBlASOTmNJmXSo9qvMYPa3DEomAPoFQFZqsSN6kuqDEIqMA=
-----END CERTIFICATE-----
`

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
	if x509 == nil {
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
	c.rebuildChains()
	return nil
}

func (c *Certificate) rebuildChains() error {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(intermediateCerts))

	chains, err := c.X509.Verify(x509.VerifyOptions{
		Intermediates: certPool,
	})
	if err != nil {
		c.log().Warningln("Failed to rebuild certificate chain.")
		return err
	}

	// The last certificate of chains is always from RootPool
	chain := chains[0]
	chain = chain[0 : len(chain)-1]

	// Copy chain
	c.TLS.Certificate = make([][]byte, len(chain))
	for idx, certificate := range chain {
		c.TLS.Certificate[idx] = certificate.Raw
	}
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
	c.rebuildChains()

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
