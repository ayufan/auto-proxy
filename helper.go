package main

import (
	"net/http"
	"strings"
)

var wsHopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; http://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
	"Sec-Websocket-Key",
	"Sec-WebSocket-Protocol",
	"Sec-Websocket-Version",
	"Sec-Websocket-Extensions",
	"Cookie",
	"Origin",
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func removeHeaders(out http.Header, headers []string) {
	for _, h := range headers {
		out.Del(h)
	}
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket" &&
	strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") == true
}
