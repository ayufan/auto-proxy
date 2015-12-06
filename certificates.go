package main

import (
	"crypto/tls"
	"github.com/Sirupsen/logrus"
	"os"
	"sync"
	"time"
)

type Certificates struct {
	list map[string]*Certificate
	lock sync.RWMutex
}

func (c *Certificates) add(certificate *Certificate) {
	if c.list == nil {
		c.list = make(map[string]*Certificate)
	}
	c.list[certificate.Name] = certificate
}

func (c *Certificates) remove(name string) {
	delete(c.list, name)
}

func (c *Certificates) load(name string, challenge CertificateChallenge) (tls *tls.Certificate, err error) {
	logrus.WithField("name", name).Debugln("Loading certificate...")

	// Just in case if certificate was added by other entity
	tls = c.find(name)
	if tls != nil {
		return tls, nil
	}

	// Create a new certificate
	if c.list == nil {
		c.list = make(map[string]*Certificate)
	}
	certificate := c.list[name]
	if certificate == nil {
		certificate = NewCertificate(name)
		c.list[name] = certificate
	}
	tls = certificate.TLS

	// Should we update (re-read?) the certificate?
	if !certificate.CanUpdate(time.Minute) {
		return
	}

	// Load the certificate
	err = certificate.Load()
	if !os.IsNotExist(err) {
		if err != nil {
			logrus.Warningln(err)
		}
		return
	}

	// Should we re-request the certificate?
	if !certificate.CanUpdate(time.Minute) {
		return
	}

	certificate.Requesting = true
	go func() {
		err := certificate.Request(challenge)
		certificate.Requesting = false
		if err != nil {
			certificate.log().WithError(err).Warningln("Failed to request a new certificate")
		}
	}()

	return certificate.TLS, nil
}

func (c Certificates) find(serverName string) *tls.Certificate {
	if certificate, ok := c.list[serverName]; ok && certificate != nil {
		if certificate.Requesting && certificate.TLS == nil {
			return nil
		}
		return certificate.TLS
	}
	return nil
}

func (c Certificates) tick(challenge CertificateChallenge) {
	for _, certificate := range c.list {
		if certificate.Requesting {
			continue
		}
		if certificate.IsExpiring(*requestBefore) && certificate.CanUpdate(*retryInterval) {
			certificate.Requesting = true
			go func(certificate *Certificate) {
				err := certificate.Request(challenge)
				certificate.Requesting = false
				if err != nil {
					certificate.log().WithError(err).Warningln("Failed to request a new certificate")
				}
			}(certificate)
		}
	}
}

func (c *Certificates) Add(certificate *Certificate) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.add(certificate)
}

func (c *Certificates) Remove(name string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.remove(name)
}

func (c *Certificates) Load(name string, challenge CertificateChallenge) (*tls.Certificate, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.load(name, challenge)
}

func (c Certificates) Find(serverName string) *tls.Certificate {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.find(serverName)
}

func (c Certificates) Tick(challenge CertificateChallenge) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	c.tick(challenge)
}
