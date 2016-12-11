package main

import (
	"crypto/tls"
	"flag"
	"github.com/Sirupsen/logrus"
	"github.com/fsouza/go-dockerclient"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"sync"
	"time"
)

var listenHttp = flag.String("listen-http", ":80", "The address to listen for HTTP requests")
var listenHttps = flag.String("listen-https", ":443", "The address to listen for HTTPS requests")
var accountKey = flag.String("account-key", "/etc/auto-proxy/account.key", "Where to store the account key")
var certsDirectory = flag.String("certs-dir", "/etc/auto-proxy/certs.d", "Where to store the generated certificates")
var requestBefore = flag.Duration("request-before", time.Hour*24*31, "When to start certificate renewal")
var retryInterval = flag.Duration("retry-interval", time.Hour, "Re-read the certificates")
var defaultCert = flag.String("default-crt", "/etc/auto-proxy/default.crt", "The path to default certificate")
var defaultKey = flag.String("default-key", "/etc/auto-proxy/default.key", "The path to default certificate key")
var useDefaultKey = flag.Bool("use-default-key", true, "All certificates will be generated with the default certificate key")
var ports = flag.String("ports", "80,8080,3000,5000", "Auto-create mapping for these ports")
var insecureSkipVerify = flag.Bool("insecure-skip-verify", false, "Disable SSL/TLS checking for proxied requests")
var http2proto = flag.Bool("http2", true, "Enable HTTP2 support")
var verbose = flag.Bool("debug", false, "Be more verbose")

type theApp struct {
	routes       Routes
	certificates Certificates
	wellKnown    map[string]string
	accessed     map[string]time.Time
	lock         sync.RWMutex
	client       *docker.Client
}

func (a *theApp) update(routes Routes) {
	logrus.Infoln("Updating routes...")
	a.routes = routes
}

func (a *theApp) ServeTLS(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if ch.ServerName == "" {
		return nil, nil
	}

	serverName := ch.ServerName

	// Try to find that certificate
	tls := a.certificates.Find(serverName)
	if tls == nil {
		// Check if we should request that certificate
		route := a.routes.Find(serverName)
		if route != nil {
			tls, _ = a.certificates.Load(serverName, a)
		}
	}

	return tls, nil
}

func (a *theApp) serveWellKnown(w http.ResponseWriter, r *http.Request) bool {
	a.lock.RLock()
	defer a.lock.RUnlock()

	if wellKnown, ok := a.wellKnown[r.RequestURI]; ok {
		io.WriteString(w, wellKnown)
		return true
	}
	return false
}

func (a *theApp) waitForRoute(route *Route) (newRoute *Route) {
	if route.AutoSleep == 0 {
		return nil
	}

	for i := 0; i < 30; i++ {
		newRoute = a.routes.Find(route.VirtualHost)
		if newRoute == nil {
			return
		}

		// We did start the route
		if len(newRoute.Servers) != 0 {
			return
		}

		logrus.Infoln("Starting containers for", route.VirtualHost, ":", route.Containers)

		// Start all containers
		var wg sync.WaitGroup
		newRoute.Start(a.client, &wg)
		wg.Wait()

		// Wait for containers to came-up
		time.Sleep(time.Second)
	}

	return nil
}

func (a *theApp) ServeHTTP(ww http.ResponseWriter, r *http.Request) {
	w := newLoggingResponseWriter(ww)
	defer w.Log(r)

	// Serve ACME responses
	if a.serveWellKnown(w, r) {
		return
	}

	// Check if we support virtual host
	route := a.routes.Find(r.Host)
	if route == nil {
		httpServerError(w, r, "no route for", r.Host)
		return
	}

	// Add auto redirect
	if r.TLS == nil && !route.EnableHTTP {
		u := *r.URL
		u.Scheme = "https"
		u.Host = r.Host
		u.User = nil

		http.Redirect(w, r, u.String(), 307)
		return
	}

	// Check if we have servers that we can use
	if len(route.Servers) == 0 {
		route = a.waitForRoute(route)
		if route == nil {
			httpServerError(w, r, "no upstreams for", r.Host)
			return
		}
	}

	a.markRoute(route)
	defer a.markRoute(route)

	// Update URL
	upstream := route.Servers[rand.Int()%len(route.Servers)]
	if upstream.Proto != "" {
		r.URL.Scheme = upstream.Proto
	} else {
		r.URL.Scheme = "http"
	}

	r.URL.Host = upstream.Host()

	// Add HSTS header
	if r.TLS != nil && !route.EnableHTTP && route.HSTS != "" {
		w.Header().Set("Strict-Transport-Security", route.HSTS)
	}

	// Pass X-Forwarded information to client
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		r.Header.Set("X-Real-IP", clientIP)
	}

	if r.TLS == nil {
		r.Header.Set("X-Forwarded-Proto", "http")
	} else {
		r.Header.Set("X-Forwarded-Proto", "https")
	}

	proxy := httputil.ReverseProxy{
		Director:      func(_ *http.Request) {},
		Transport:     &defaultTransport,
		FlushInterval: time.Minute,
	}
	proxy.ServeHTTP(w, r)

	w.Message = upstream.String()
}

func (a *theApp) AddCertificate(name string, certificate *tls.Certificate) {
	a.certificates.Add(&Certificate{
		Name: name,
		TLS:  certificate,
	})
}

func (a *theApp) RemoveCertificate(name string) {
	a.certificates.Remove(name)
}

func (a *theApp) AddHttpUri(uriPath, resource string) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.wellKnown == nil {
		a.wellKnown = make(map[string]string)
	}
	a.wellKnown[uriPath] = resource
}

func (a *theApp) RemoveHttpUri(uriPath string) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.wellKnown != nil {
		delete(a.wellKnown, uriPath)
	}
}

func (a *theApp) markRoute(route *Route) {
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.accessed == nil {
		a.accessed = make(map[string]time.Time)
	}
	a.accessed[route.VirtualHost] = time.Now()
}

func (a *theApp) shouldRouteSleep(route *Route) bool {
	if route.AutoSleep == 0 {
		return false
	}

	a.lock.Lock()
	defer a.lock.Unlock()
	return time.Since(a.accessed[route.VirtualHost]) > route.AutoSleep
}

func (a *theApp) sleepUpdate() {
	var wg sync.WaitGroup

	routes := a.routes

	for _, route := range routes {
		if a.shouldRouteSleep(route) && len(route.Servers) != 0 {
			logrus.Infoln("Stopping containers for", route.VirtualHost, "due to inactivity:", route.Containers)
			route.Stop(a.client, &wg)
		}
	}

	wg.Wait()
}

func main() {
	var wg sync.WaitGroup
	var app theApp

	flag.Parse()

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// Create directories
	os.MkdirAll(*certsDirectory, 0700)
	os.MkdirAll(path.Dir(*accountKey), 0700)
	os.MkdirAll(path.Dir(*defaultCert), 0700)
	os.MkdirAll(path.Dir(*defaultKey), 0700)

	defaultTransport = http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *insecureSkipVerify,
		},
	}

	// Load or create default certificate
	defaultCertificate = &Certificate{
		Name:            "default",
		CertificateFile: *defaultCert,
		KeyFile:         *defaultKey,
	}
	err := defaultCertificate.Load()
	if os.IsNotExist(err) {
		err = defaultCertificate.CreateSelfSigned()
		if err != nil {
			logrus.Fatalln(err)
		}
	} else if err != nil {
		logrus.Fatalln(err)
	}

	app.client, err = docker.NewClientFromEnv()
	if err != nil {
		logrus.Errorln("Unable to connect to docker daemon:", err)
		os.Exit(1)
	}

	// Listen for HTTP
	if *listenHttp != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ListenAndServe(*listenHttp, &app)
			if err != nil {
				logrus.Fatalln(err)
			}
		}()
	}

	// Listen for HTTPS
	if *listenHttps != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := ListenAndServeTLS(*listenHttps, defaultCertificate, &app)
			if err != nil {
				logrus.Fatalln(err)
			}
		}()
	}

	// Watch for docker events to generate routes
	go func() {
		app.watchEvents()
	}()

	// Renew certificates
	go func() {
		for {
			time.Sleep(time.Hour)
			app.certificates.Tick(&app)
		}
	}()

	// Sleep support
	go func() {
		for {
			time.Sleep(time.Second * 10)
			app.sleepUpdate()
		}
	}()

	wg.Wait()
}
