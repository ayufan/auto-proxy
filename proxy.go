package main

import (
	"fmt"
	"net/http"
	"time"
)

var defaultTransport http.Transport

type loggingResponseWriter struct {
	rw      http.ResponseWriter
	status  int
	written int64
	started time.Time
	Message string
}

func newLoggingResponseWriter(rw http.ResponseWriter) *loggingResponseWriter {
	return &loggingResponseWriter{
		rw:      rw,
		started: time.Now(),
	}
}

func (l *loggingResponseWriter) Header() http.Header {
	return l.rw.Header()
}

func (l *loggingResponseWriter) Write(data []byte) (n int, err error) {
	if l.status == 0 {
		l.status = http.StatusOK
	}
	n, err = l.rw.Write(data)
	l.written += int64(n)
	return
}

func (l *loggingResponseWriter) WriteHeader(status int) {
	l.rw.WriteHeader(status)
	if l.status == 0 {
		l.status = status
	}
}

func (l *loggingResponseWriter) Log(r *http.Request) {
	duration := time.Since(l.started)
	fmt.Printf("%s %s - - [%s] %q %d %d %q %q %f %q\n",
		r.Host, r.RemoteAddr, l.started,
		fmt.Sprintf("%s %s %s", r.Method, r.RequestURI, r.Proto),
		l.status, l.written, r.Referer(), r.UserAgent(),
		duration.Seconds(), l.Message,
	)
}

func httpServerError(w http.ResponseWriter, r *http.Request, a ...interface{}) {
	w.WriteHeader(503)
	fmt.Fprintln(w, a...)
}
