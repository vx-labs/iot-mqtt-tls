FROM vxlabs/glide as builder

RUN mkdir -p $GOPATH/src/github.com/vx-labs
WORKDIR $GOPATH/src/github.com/vx-labs/iot-mqtt-tls
RUN mkdir release
COPY glide* ./
RUN glide install
COPY . ./
RUN go test $(glide nv)
