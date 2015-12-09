FROM alpine

COPY . /go/src/auto-proxy

ENV GOROOT=/usr/lib/go \
    GOPATH=/go \
    GOBIN=/go/bin \
    PATH=$PATH:$GOROOT/bin:$GOPATH/bin

RUN echo "http://dl-4.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories && \
  apk add -U git ca-certificates go && \
  go get -v auto-proxy && \
  apk del git go && \
  rm -rf /go/src /go/pkg /var/cache/apk/

VOLUME ["/etc/auto-proxy"]

ENTRYPOINT ["/go/bin/auto-proxy"]
