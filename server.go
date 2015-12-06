package main

import (
	"crypto/tls"
	"golang.org/x/net/http2"
	"io/ioutil"
	"net/http"
	"os"
)

type TLSHandler interface {
	http.Handler
	ServeTLS(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBdzCCASOgAwIBAgIBADALBgkqhkiG9w0BAQUwEjEQMA4GA1UEChMHQWNtZSBD
bzAeFw03MDAxMDEwMDAwMDBaFw00OTEyMzEyMzU5NTlaMBIxEDAOBgNVBAoTB0Fj
bWUgQ28wWjALBgkqhkiG9w0BAQEDSwAwSAJBAN55NcYKZeInyTuhcCwFMhDHCmwa
IUSdtXdcbItRB/yfXGBhiex00IaLXQnSU+QZPRZWYqeTEbFSgihqi1PUDy8CAwEA
AaNoMGYwDgYDVR0PAQH/BAQDAgCkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1Ud
EwEB/wQFMAMBAf8wLgYDVR0RBCcwJYILZXhhbXBsZS5jb22HBH8AAAGHEAAAAAAA
AAAAAAAAAAAAAAEwCwYJKoZIhvcNAQEFA0EAAoQn/ytgqpiLcZu9XKbCJsJcvkgk
Se6AbGXgSlq+ZCEVo0qIwSgeBqmsJxUu7NCSOwVJLYNEBO2DtIxoYVk+MA==
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAN55NcYKZeInyTuhcCwFMhDHCmwaIUSdtXdcbItRB/yfXGBhiex0
0IaLXQnSU+QZPRZWYqeTEbFSgihqi1PUDy8CAwEAAQJBAQdUx66rfh8sYsgfdcvV
NoafYpnEcB5s4m/vSVe6SU7dCK6eYec9f9wpT353ljhDUHq3EbmE4foNzJngh35d
AekCIQDhRQG5Li0Wj8TM4obOnnXUXf1jRv0UkzE9AHWLG5q3AwIhAPzSjpYUDjVW
MCUXgckTpKCuGwbJk7424Nb8bLzf3kllAiA5mUBgjfr/WtFSJdWcPQ4Zt9KTMNKD
EUO0ukpTwEIl6wIhAMbGqZK3zAAFdq8DD2jPx+UJXnh0rnOkZBzDtJ6/iN69AiEA
1Aq8MJgTaYsDQWyU/hDq5YkDJc9e9DSCvUIzqxQWMQE=
-----END RSA PRIVATE KEY-----`)

func ListenAndServe(addr string, handler http.Handler) error {
	// create server
	server := &http.Server{Addr: addr, Handler: handler}
	err := http2.ConfigureServer(server, &http2.Server{})
	if err != nil {
		return err
	}

	return server.ListenAndServe()
}

func ListenAndServeTLS(addr string, certificate *Certificate, handler TLSHandler) error {
	certFile, err := ioutil.TempFile("", "cert_")
	if err != nil {
		return err
	}
	defer certFile.Close()
	_, err = certFile.Write(localhostCert)
	if err != nil {
		return err
	}
	certFile.Close()
	defer os.Remove(certFile.Name())

	keyFile, err := ioutil.TempFile("", "cert_")
	if err != nil {
		return err
	}
	defer keyFile.Close()
	_, err = keyFile.Write(localhostKey)
	if err != nil {
		return err
	}
	keyFile.Close()
	defer os.Remove(keyFile.Name())

	// create server
	server := &http.Server{Addr: addr, Handler: handler}
	server.TLSConfig = &tls.Config{}
	server.TLSConfig.GetCertificate = handler.ServeTLS

	err = http2.ConfigureServer(server, &http2.Server{})
	if err != nil {
		return err
	}

	return server.ListenAndServeTLS(certificate.CertificateFile, certificate.KeyFile)
}
