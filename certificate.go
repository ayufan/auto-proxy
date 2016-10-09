package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRANOxciY0IzLc9AUoUSrsnGowDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTYxMDA2MTU0MzU1
WhcNMjExMDA2MTU0MzU1WjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDMwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCc0wzwWuUuR7dyXTeDs2hjMOrX
NSYZJeG9vjXxcJIvt7hLQQWrqZ41CFjssSrEaIcLo+N15Obzp2JxunmBYB/XkZqf
89B4Z3HIaQ6Vkc/+5pnpYDxIzH7KTXcSJJ1HG1rrueweNwAcnKx7pwXqzkrrvUHl
Npi5y/1tPJZo3yMqQpAMhnRnyH+lmrhSYRQTP2XpgofL2/oOVvaGifOFP5eGr7Dc
Gu9rDZUWfcQroGWymQQ2dYBrrErzG5BJeC+ilk8qICUpBMZ0wNAxzY8xOJUWuqgz
uEPxsR/DMH+ieTETPS02+OP88jNquTkxxa/EjQ0dZBYzqvqEKbbUC8DYfcOTAgMB
AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU
BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB
FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBSo
SmpjBH3duubRObemRWXv86jsoTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF
BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG
AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD
VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB
ABnPdSA0LTqmRf/Q1eaM2jLonG4bQdEnqOJQ8nCqxOeTRrToEKtwT++36gTSlBGx
A/5dut82jJQ2jxN8RI8L9QFXrWi4xXnA2EqA10yjHiR6H9cj6MFiOnb5In1eWsRM
UM2v3e9tNsCAgBukPHAg1lQh07rvFKm/Bz9BCjaxorALINUfZ9DD64j2igLIxle2
DPxW8dI/F2loHMjXZjqG8RkqZUdoxtID5+90FgsGIfkMpqgRS05f4zPbCEHqCXl1
eO5HyELTgcVlLXXQDgAWnRzut1hFJeczY1tjQQno6f6s+nMydLN26WuU4s3UYvOu
OsUxRlJu7TSRHqDC3lSE5XggVkzdaPkuKGQbGpny+01/47hfXXNB7HntWNZ6N2Vw
p7G6OfY+YQrZwIaQmhrIqJZuigsrbe3W+gdn5ykE9+Ky0VgVUsfxo52mwFYs1JKY
2PGDuWx8M6DlS6qQkvHaRUo0FMd8TsSlbF0/v965qGFKhSDeQoMpYnwcmQilRh/0
ayLThlHLN81gSkJjVrPI0Y8xCVPB4twb1PFUd2fPM3sA1tJ83sZ5v8vgFv2yofKR
PB0t6JzUA81mSqM3kxl5e+IZwhYAyO0OTg3/fs8HqGTNKd9BqoUwSRBzp06JMg5b
rUCGwbCUDI0mxadJ3Bz4WxR6fyNpBK2yAinWEsikxqEt
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIRAJObmZ6kjhYNW0JZtD0gE9owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTYxMDA2MTU0NDM0
WhcNMjExMDA2MTU0NDM0WjBKMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDEjMCEGA1UEAxMaTGV0J3MgRW5jcnlwdCBBdXRob3JpdHkgWDQwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDhJHRCe7eRMdlz/ziq2M5EXLc5
CtxErg29RbmXN2evvVBPX9MQVGv3QdqOY+ZtW8DoQKmMQfzRA4n/YmEJYNYHBXia
kL0aZD5P3M93L4lry2evQU3FjQDAa/6NhNy18pUxqOj2kKBDSpN0XLM+Q2lLiSJH
dFE+mWTDzSQB+YQvKHcXIqfdw2wITGYvN3TFb5OOsEY3FmHRUJjIsA9PWFN8rPba
LZZhUK1D3AqmT561Urmcju9O30azMdwg/GnCoyB1Puw4GzZOZmbS3/VmpJMve6YO
lD5gPUpLHG+6tE0cPJFYbi9NxNpw2+0BOXbASefpNbUUBpDB5ZLiEP1rubSFAgMB
AAGjggFnMIIBYzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADBU
BgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIB
FiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMB0GA1UdDgQWBBTF
satOTLHNZDCTfsGEmQWr5gPiJTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
LnJvb3QteDEubGV0c2VuY3J5cHQub3JnMHIGCCsGAQUFBwEBBGYwZDAwBggrBgEF
BQcwAYYkaHR0cDovL29jc3Aucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcvMDAGCCsG
AQUFBzAChiRodHRwOi8vY2VydC5yb290LXgxLmxldHNlbmNyeXB0Lm9yZy8wHwYD
VR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wDQYJKoZIhvcNAQELBQADggIB
AF4tI1yGjZgld9lP01+zftU3aSV0un0d2GKUMO7GxvwTLWAKQz/eT+u3J4+GvpD+
BMfopIxkJcDCzMChjjZtZZwJpIY7BatVrO6OkEmaRNITtbZ/hCwNkUnbk3C7EG3O
GJZlo9b2wzA8v9WBsPzHpTvLfOr+dS57LLPZBhp3ArHaLbdk33lIONRPt9sseDEk
mdHnVmGmBRf4+J0Wy67mddOvz5rHH8uzY94raOayf20gzzcmqmot4hPXtDG4Y49M
oFMMT2kcWck3EOTAH6QiGWkGJ7cxMfSL3S0niA6wgFJtfETETOZu8AVDgENgCJ3D
S0bz/dhVKvs3WRkaKuuR/W0nnC2VDdaFj4+CRF8LGtn/8ERaH48TktH5BDyDVcF9
zfJ75Scxcy23jAL2N6w3n/t3nnqoXt9Im4FprDr+mP1g2Z6Lf2YA0jE3kZalgZ6l
NHu4CmvJYoOTSJw9X2qlGl1K+B4U327rG1tRxgjM76pN6lIS02PMECoyKJigpOSB
u4V8+LVaUMezCJH9Qf4EKeZTHddQ1t96zvNd2s9ewSKx/DblXbKsBDzIdHJ+qi6+
F9DIVM5/ICdtDdulOO+dr/BXB+pBZ3uVxjRANvJKKpdxkePyluITSNZHbanWRN07
gMvwBWOL060i4VrL9er1sBQrRjU9iNpZQGTnLVAxQVFu
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

func (c *Certificate) certificateList(verifiedChains [][]*x509.Certificate) (certificates [][]byte) {
	seenCertificates := make(map[string]bool, 0)

	for _, verifiedChain := range verifiedChains {
		for _, certificate := range verifiedChain {
			signature := hex.EncodeToString(certificate.Signature)
			if !seenCertificates[signature] {
				seenCertificates[signature] = true
				certificates = append(certificates, certificate.Raw)
			}
		}
	}

	return
}

func (c *Certificate) rebuildChains() error {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM([]byte(intermediateCerts))

	verifiedChains, err := c.X509.Verify(x509.VerifyOptions{
		Intermediates: certPool,
	})
	if err != nil {
		c.log().Warningln("Failed to rebuild certificate chain.")
		return err
	}

	c.TLS.Certificate = c.certificateList(verifiedChains)
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
	return c.finish(certificate.Certificate, key)
}
