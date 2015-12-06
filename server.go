package main

import (
	"crypto/tls"
	"golang.org/x/net/http2"
	"net/http"
)

type TLSHandler interface {
	http.Handler
	ServeTLS(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

func ListenAndServe(addr string, handler http.Handler) error {
	// create server
	server := &http.Server{Addr: addr, Handler: handler}

	if *http2proto {
		err := http2.ConfigureServer(server, &http2.Server{})
		if err != nil {
			return err
		}
	}

	return server.ListenAndServe()
}

func ListenAndServeTLS(addr string, certificate *Certificate, handler TLSHandler) error {
	// create server
	server := &http.Server{Addr: addr, Handler: handler}
	server.TLSConfig = &tls.Config{}
	server.TLSConfig.GetCertificate = handler.ServeTLS

	if *http2proto {
		err := http2.ConfigureServer(server, &http2.Server{})
		if err != nil {
			return err
		}
	}

	return server.ListenAndServeTLS(certificate.CertificateFile, certificate.KeyFile)
}
