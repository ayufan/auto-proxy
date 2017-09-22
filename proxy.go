package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

var defaultTransport http.Transport

type loggingResponseWriter struct {
	rw       http.ResponseWriter
	r        *http.Request
	status   int
	hijacked bool
	written  int64
	started  time.Time
	Message  string
}

func newLoggingResponseWriter(rw http.ResponseWriter, r *http.Request) *loggingResponseWriter {
	return &loggingResponseWriter{
		rw:      rw,
		r:       r,
		started: time.Now(),
	}
}

func (l *loggingResponseWriter) Header() http.Header {
	return l.rw.Header()
}

func (l *loggingResponseWriter) Write(data []byte) (n int, err error) {
	if l.hijacked {
		return
	}

	if l.status == 0 {
		l.status = http.StatusOK
	}
	n, err = l.rw.Write(data)
	l.written += int64(n)
	return
}

func (l *loggingResponseWriter) WriteHeader(status int) {
	if l.hijacked {
		return
	}

	l.rw.WriteHeader(status)
	if l.status == 0 {
		l.status = status
	}
}

func (l *loggingResponseWriter) IsFinished() bool {
	return l.status != 0 || l.hijacked
}

func (l *loggingResponseWriter) Log() {
	duration := time.Since(l.started)
	fmt.Printf("%s %s - - [%s] %q %d %d %q %q %f %q\n",
		l.r.Host, l.r.RemoteAddr, l.started,
		fmt.Sprintf("%s %s %s", l.r.Method, l.r.RequestURI, l.r.Proto),
		l.status, l.written, l.r.Referer(), l.r.UserAgent(),
		duration.Seconds(), l.Message,
	)
}

func (l *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijack, _ := l.rw.(http.Hijacker); hijack != nil {
		conn, rw, err := hijack.Hijack()
		if err != nil {
			l.Message = "hijack error: " + err.Error()
		} else {
			l.hijacked = true
			l.Message = "hijack ok: " + conn.RemoteAddr().String()
		}
		l.Log()

		return conn, rw, err
	}

	return nil, nil, errors.New("cannot hijack connection")
}

func httpServerError(w http.ResponseWriter, r *http.Request, a ...interface{}) {
	w.WriteHeader(503)
	fmt.Fprintln(w, a...)
}
