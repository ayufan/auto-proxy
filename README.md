你好！
很冒昧用这样的方式来和你沟通，如有打扰请忽略我的提交哈。我是光年实验室（gnlab.com）的HR，在招Golang开发工程师，我们是一个技术型团队，技术氛围非常好。全职和兼职都可以，不过最好是全职，工作地点杭州。
我们公司是做流量增长的，Golang负责开发SAAS平台的应用，我们做的很多应用是全新的，工作非常有挑战也很有意思，是国内很多大厂的顾问。
如果有兴趣的话加我微信：13515810775  ，也可以访问 https://gnlab.com/，联系客服转发给HR。
![License MIT](https://img.shields.io/badge/license-MIT-blue.svg) [![](https://badge.imagelayers.io/ayufan/auto-proxy:latest.svg)](https://imagelayers.io/?images=ayufan/auto-proxy:latest)

[auto-proxy](https://hub.docker.com/r/ayufan/auto-proxy/) sets up a container running go http server with built-in Let's Encrypt support to automatically generate SSL/TLS certificates and built-in support for HTTP2.

### Usage

To run it:

    $ docker run -d -p 80:80 -p 443:443 -v /path/to/config/dir:/etc/auto-proxy -v /var/run/docker.sock:/var/run/docker.sock:ro ayufan/auto-proxy

Then start any containers you want proxied with an env var `VIRTUAL_HOST=subdomain.youdomain.com`

    $ docker run -e VIRTUAL_HOST=foo.bar.com  ...

The containers being proxied must [expose](https://docs.docker.com/reference/run/#expose-incoming-ports) the port to be proxied, either by using the `EXPOSE` directive in their `Dockerfile` or by using the `--expose` flag to `docker run` or `docker create`.

Provided your DNS is setup to forward foo.bar.com to the a host running auto-proxy, the request will be routed to a container with the VIRTUAL_HOST env var set.

### Multiple Ports

If your container exposes multiple ports, auto-proxy will check if any of these ports is exposed 80, 8080, 3000, 5000 and it will use it. If you need to specify a different port, you can set a VIRTUAL_PORT env var to select a different one.

### Multiple Hosts

If you need to support multiple virtual hosts for a container, you can separate each entry with commas. For example, `foo.bar.com,baz.bar.com,bar.com` and each host will be setup the same.

### Wildcard Hosts

You can also use wildcards at the beginning and the end of host name, like `*.bar.com`.

### SSL Backends

If you would like to connect to your backend using HTTPS instead of HTTP, set `VIRTUAL_PROTO=https` on the backend container.

### SSL Support with Let's Encrypt

Certificates for SSL are automatically generated using [Let's Encrypt](https://letsencrypt.org/).
They are generated on first use.

You can put own certificate by adding file to `/path/to/config/certs` with the certificate and private key.
The certificate and keys should be named after the virtual host with a `.crt` and
`.key` extension.  For example, a container with `VIRTUAL_HOST=foo.bar.com` should have a
`foo.bar.com.crt` and `foo.bar.com.key` file in the certs directory.

The default certificate used for all hosts for which the certificate can't be generated is stored in:
`/path/to/config/default.crt` and `/path/to/config/default.key`

### Configure HSTS

By default each site uses HSTS. To disable or overwrite HSTS specify: `HTTP_HSTS`.

#### Wildcard Certificates

Wildcard certificates and keys should be named after the domain name with a `.crt` and `.key` extension.
For example `VIRTUAL_HOST=foo.bar.com` would use cert name `bar.com.crt` and `bar.com.key`.

#### How SSL Support Works

The default SSL cipher configuration is used of golang.
The configuration also enables HSTS, and SSL session caches.

The port 80 is always exposed to 443 unless the `ENABLE_HTTP=true` is specified as environment variable for running container.

Till the certificate is generated the `default.crt` will be used to serve the site.
The `default.crt` is generated on first run of auto-proxy and can be overwritten later.

#### Auto-sleep

Auto-proxy allows you to configure containers to auto-sleep after in-activity time by specifying `AUTO_SLEEP` variable in `time.Duration` format.
For example: `AUTO_SLEEP=30s` or `AUTO_SLEEP=30m`.

### Contributing

Before submitting pull requests or issues, please check github to make sure an existing issue or pull request is not already open.

#### Running Tests Locally

TBD

### Use latest master

    $ docker run -d -p 80:80 -p 443:443 -v /path/to/config/dir:/etc/auto-proxy -v /var/run/docker.sock:/var/run/docker.sock:ro ayufan/auto-proxy:master

### Thanks

The idea of creating such proxy was borowed from [jwilder/nginx-proxy](https://github.com/jwilder/nginx-proxy) which I used with great success for long time.
Part of the docs are also borowed from there.

