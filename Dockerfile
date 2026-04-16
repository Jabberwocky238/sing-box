FROM golang:1.23-alpine AS builder
COPY . /go/src/github.com/sagernet/sing-box
WORKDIR /go/src/github.com/sagernet/sing-box
ARG GOPROXY=""
ENV GOPROXY=${GOPROXY}
ENV CGO_ENABLED=0
RUN apk add git build-base make \
    && make build \
    && mv sing-box /go/bin/sing-box

FROM alpine AS dist
RUN apk add --no-cache bash tzdata ca-certificates nftables
COPY --from=builder /go/bin/sing-box /usr/local/bin/sing-box
ENTRYPOINT ["sing-box"]
