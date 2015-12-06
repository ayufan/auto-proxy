package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

type Upstream struct {
	IP    string
	Port  int
	Proto string
}

func (u *Upstream) Host() string {
	return fmt.Sprintf("%s:%d", u.IP, u.Port)
}

type RouteBuilder struct {
	VirtualHost []string
	Upstream    Upstream
}

func NewRouteBuilder() RouteBuilder {
	return RouteBuilder{
		Upstream: Upstream{
			Proto: "http",
		},
	}
}

func (r *RouteBuilder) isValid() bool {
	return len(r.VirtualHost) > 0 && r.Upstream.IP != "" && r.Upstream.Port != 0
}

func (r *RouteBuilder) parse(env string) bool {
	keyValue := strings.SplitN(env, "=", 2)
	if len(keyValue) != 2 {
		return false
	}

	switch keyValue[0] {
	case "VIRTUAL_HOST":
		r.VirtualHost = strings.Split(keyValue[1], ",")
	case "VIRTUAL_PORT":
		port, _ := strconv.Atoi(keyValue[1])
		r.Upstream.Port = port
	case "VIRTUAL_PROTO":
		r.Upstream.Proto = keyValue[1]
	default:
		return false
	}

	return true
}

type Route struct {
	VirtualHost string
	Wildcard    bool
	Servers     []Upstream
}

type Routes map[string]*Route

func (r *Routes) Add(b RouteBuilder) bool {
	if !b.isValid() {
		return false
	}

	for _, host := range b.VirtualHost {
		route := r.GetVhost(host)
		route.Servers = append(route.Servers, b.Upstream)
	}
	return true
}

func (r Routes) GetVhost(vhost string) *Route {
	key := strings.TrimPrefix(vhost, "*.")
	route := r[key]
	if route == nil {
		route = &Route{}
		r[key] = route
	}
	route.VirtualHost = vhost
	route.Wildcard = strings.HasPrefix(vhost, "*.")
	return route
}

func (r Routes) trimSubdomain(s string) string {
	if idx := strings.Index(s, "."); idx >= 0 {
		return s[idx+1:]
	} else {
		return s
	}
}

func (r Routes) Find(vhost string) *Route {
	if r == nil {
		return nil
	} else if route, ok := r[vhost]; ok {
		return route
	} else if route, ok := r[r.trimSubdomain(vhost)]; ok && route.Wildcard {
		if matched, _ := filepath.Match(route.VirtualHost, vhost); matched {
			return route
		} else {
			return nil
		}
	} else {
		return nil
	}
}
