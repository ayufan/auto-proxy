package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

type Upstream struct {
	Container string
	IP        string
	Port      string
	Proto     string
}

func (u *Upstream) Host() string {
	return fmt.Sprintf("%s:%s", u.IP, u.Port)
}

func (u *Upstream) String() string {
	return fmt.Sprintf("%s (%s:%s)", u.Container, u.IP, u.Port)
}

type RouteBuilder struct {
	VirtualHost []string
	Upstream    Upstream
	EnableHTTP  bool
	HSTS        string
	Suffix      string
}

func FindRoutes(envs ...string) (routes []RouteBuilder) {
	for i := 0; i < 10; i++ {
		suffix := ""
		if i > 0 {
			suffix = "_" + strconv.Itoa(i)
		}

		route := NewRouteBuilder(suffix)
		route.ParseAll(envs...)

		if route.haveVirtualHosts() {
			routes = append(routes, route)
		}
	}

	return
}

func NewRouteBuilder(suffix string) RouteBuilder {
	return RouteBuilder{
		Upstream: Upstream{
			Proto: "http",
		},
		EnableHTTP: false,
		HSTS:       "max-age=31536000",
		Suffix:     suffix,
	}
}

func (r *RouteBuilder) isValid() bool {
	return r.haveVirtualHosts() && r.Upstream.IP != "" && r.Upstream.Port != ""
}

func (r *RouteBuilder) haveVirtualHosts() bool {
	return len(r.VirtualHost) > 0
}

func (r *RouteBuilder) Parse(env string) bool {
	keyValue := strings.SplitN(env, "=", 2)
	if len(keyValue) != 2 {
		return false
	}

	switch keyValue[0] {
	case "VIRTUAL_HOST" + r.Suffix:
		r.VirtualHost = strings.Split(keyValue[1], ",")
	case "VIRTUAL_PORT" + r.Suffix:
		r.Upstream.Port = keyValue[1]
	case "VIRTUAL_PROTO" + r.Suffix:
		r.Upstream.Proto = keyValue[1]
	case "ENABLE_HTTP" + r.Suffix:
		flag, _ := strconv.ParseBool(keyValue[1])
		r.EnableHTTP = flag
	case "HTTP_HSTS" + r.Suffix:
		r.HSTS = keyValue[1]
	default:
		return false
	}

	return true
}

func (r *RouteBuilder) ParseAll(envs ...string) {
	for _, env := range envs {
		r.Parse(env)
	}
}

type Route struct {
	VirtualHost string
	Wildcard    bool
	EnableHTTP  bool
	HSTS        string
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
		route.EnableHTTP = b.EnableHTTP
		route.HSTS = b.HSTS
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
