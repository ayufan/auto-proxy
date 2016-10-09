FROM alpine

COPY . /go/src/auto-proxy

ENV GOROOT=/usr/lib/go \
    GOPATH=/go \
    GOBIN=/go/bin \
    PATH=$PATH:$GOROOT/bin:$GOPATH/bin

RUN apk add -U git ca-certificates go build-base && \
  go get -v auto-proxy && \
  apk del git go build-base && \
  rm -rf /go/src /go/pkg /var/cache/apk/

VOLUME ["/etc/auto-proxy"]

ENTRYPOINT ["/go/bin/auto-proxy"]
