FROM alpine

COPY . /go/src/auto-proxy

ENV GOROOT=/usr/lib/go \
    GOPATH=/go \
    GOBIN=/go/bin \
    PATH=$PATH:$GOROOT/bin:$GOPATH/bin

RUN apk add -U git ca-certificates go && \
  go get -v auto-proxy && \
  apk del git go && \
  rm -rf /go/src /go/pkg /var/cache/apk/

ENTRYPOINT ["/go/bin/auto-proxy"]
