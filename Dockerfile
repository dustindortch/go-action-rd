FROM golang:1.24 AS builder

ENV GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64

WORKDIR /app

COPY go.mod go.mod
COPY main.go main.go

RUN go get
RUN go build \
  -ldflags "-s -w -extldflags '-static'" \
  -o build/action .

RUN echo "nobody:x:65534:65534:nobody:/:" > /etc_passwd

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc_passwd /etc/passwd
COPY --from=builder /app/build/action /bin/action

USER nobody
ENTRYPOINT ["/bin/action"]