package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/ericchiang/letsencrypt"
	"io/ioutil"
	"os"
)

type LetsEncrypt struct {
	client     *letsencrypt.Client
	accountKey *rsa.PrivateKey
}

func (e *LetsEncrypt) ensureClient() error {
	if e.client != nil {
		return nil
	}

	client, err := letsencrypt.NewClient("https://acme-v01.api.letsencrypt.org/directory")
	if err != nil {
		return err
	}

	e.client = client
	return nil
}

func (e *LetsEncrypt) createAccountKey() error {
	err := e.ensureClient()
	if err != nil {
		return err
	}

	// Create a private key for your account and register
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// Register the key
	if _, err := e.client.NewRegistration(key); err != nil {
		return err
	}

	// Write account key to file
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	err = ioutil.WriteFile(*accountKey, data, 0600)
	if err != nil {
		return err
	}

	e.accountKey = key
	return nil
}

func (e *LetsEncrypt) loadAccountKey() error {
	data, err := ioutil.ReadFile(*accountKey)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("pem decode: no key found")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	e.accountKey = key
	return nil
}

func (e *LetsEncrypt) ensureAccountKey() (err error) {
	if e.accountKey != nil {
		return nil
	}

	err = e.loadAccountKey()
	if os.IsNotExist(err) {
		err = e.createAccountKey()
	}
	return err
}

func (e *LetsEncrypt) requestChallenge(serverName, challengeName string) (challenge letsencrypt.Challenge, err error) {
	err = e.ensureClient()
	if err != nil {
		return
	}

	err = e.ensureAccountKey()
	if err != nil {
		return
	}

	// ask for a set of challenges for a given domain
	auth, _, err := e.client.NewAuthorization(e.accountKey, "dns", serverName)
	if err != nil {
		return
	}

	// Find possible challenges
	challenges := auth.Combinations(challengeName)
	if len(challenges) == 0 {
		err = errors.New("no supported challenge combinations")
		return
	}

	challenge = challenges[0][0]
	return
}

func (e *LetsEncrypt) requestTlsSni(serverName string) (certs map[string]*tls.Certificate, challenge letsencrypt.Challenge, err error) {
	challenge, err = e.requestChallenge(serverName, letsencrypt.ChallengeTLSSNI)
	if err != nil {
		return
	}

	// Request TLS-SNI-01 challenge
	certs, err = challenge.TLSSNI(e.accountKey)
	return
}

func (e *LetsEncrypt) requestHttp(serverName string) (urlPath, resource string, challenge letsencrypt.Challenge, err error) {
	challenge, err = e.requestChallenge(serverName, letsencrypt.ChallengeHTTP)
	if err != nil {
		return
	}

	// Request HTTP-01 challenge
	urlPath, resource, err = challenge.HTTP(e.accountKey)
	return
}

func (e *LetsEncrypt) finishChallenge(challenge letsencrypt.Challenge) (err error) {
	err = e.ensureClient()
	if err != nil {
		return
	}

	err = e.ensureAccountKey()
	if err != nil {
		return
	}

	// Notify about the challenge
	err = e.client.ChallengeReady(e.accountKey, challenge)
	if err != nil {
		return
	}
	return
}

func (e *LetsEncrypt) createCertificate(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	err := e.ensureClient()
	if err != nil {
		return nil, err
	}

	err = e.ensureAccountKey()
	if err != nil {
		return nil, err
	}

	return e.client.NewCertificate(e.accountKey, csr)
}
