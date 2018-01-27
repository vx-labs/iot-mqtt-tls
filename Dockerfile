FROM vxlabs/glide as builder

RUN mkdir -p $GOPATH/src/github.com/vx-labs
WORKDIR $GOPATH/src/github.com/vx-labs/iot-mqtt-tls
RUN mkdir release
COPY glide* ./
RUN glide install
COPY . ./
RUN go test $(glide nv) && \
    go build -buildmode=exe -a -o /bin/tls ./cmd/tls

FROM alpine
EXPOSE 1883
ENTRYPOINT ["/usr/bin/server"]
RUN apk -U add ca-certificates && \
    rm -rf /var/cache/apk/*
COPY --from=builder /bin/tls /usr/bin/server

