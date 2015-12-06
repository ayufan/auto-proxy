package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

func httpLog(statusCode int, written int64, r *http.Request, started time.Time) {
	fmt.Printf("%s %s - - [%s] %q %d %d %q %q\n",
		r.Host, r.RemoteAddr, started,
		fmt.Sprintf("%s %s %s", r.Method, r.RequestURI, r.Proto),
		statusCode, written, r.Referer(), r.UserAgent(),
	)
}

func httpServerError(w http.ResponseWriter, r *http.Request, a ...interface{}) {
	w.WriteHeader(503)
	written, _ := fmt.Fprintln(w, a...)
	httpLog(503, int64(written), r, time.Now())
}

func httpProxyRequest(upstream Upstream, w http.ResponseWriter, r *http.Request) {
	u, err := url.ParseRequestURI(r.RequestURI)
	if err != nil {
		httpServerError(w, r, "Failed to parse:", r.RequestURI, "with:", err)
		return
	}

	started := time.Now()

	u.Scheme = "http"
	if upstream.Proto != "" {
		u.Scheme = upstream.Proto
	}
	u.Host = upstream.Host()

	req := http.Request{
		Method:        r.Method,
		URL:           u,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        r.Header,
		Body:          r.Body,
		ContentLength: r.ContentLength,
		Host:          r.Host,
	}

	res, err := http.DefaultTransport.RoundTrip(&req)
	if err != nil {
		httpServerError(w, r, "Failed to execute request to:", u.String(), "with:", err)
		return
	}

	defer res.Body.Close()
	for k, v := range res.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(res.StatusCode)
	written, _ := io.Copy(w, res.Body)
	httpLog(res.StatusCode, written, r, started)
}
