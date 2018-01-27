all: build
test:
	go test $$(glide nv)
pb::
	go generate ./...
build:
	docker build -t vxlabs/iot-mqtt-tls .
deploy:
	docker run --rm \
	    -e DOCKER_REGISTRY=$$DOCKER_REGISTRY \
        -e KUBE_URL=$$KUBE_URL \
        -e KUBE_NAMESPACE=$$IOT_KUBE_NAMESPACE \
        -e KUBE_TOKEN=$$IOT_KUBE_TOKEN \
        -e KUBE_DOMAIN=$$KUBE_DOMAIN \
        -e COMMIT_HASH=$$CI_COMMIT_SHA \
        -e ENVIRONMENT_PUBLIC_NAME=mqtt.$$IOT_ENVIRONMENT_NAME \
        -e APPROLE_ID=$$IOT_MQTT_TLS_APPROLE_ID \
        -e APPROLE_SECRET=$$IOT_MQTT_TLS_APPROLE_SECRET \
        -v $$(pwd)/kubernetes-spec.yml.template:/media/template:ro \
        ${DOCKER_REGISTRY}/vxlabs/k8s-deploy
