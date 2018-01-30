all: build
test:
	go test $$(glide nv)
pb::
	go generate ./...
build:
	docker build -t vxlabs/iot-mqtt-tls .
