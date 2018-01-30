package main

import (
	"github.com/vx-labs/iot-mqtt-tls/api"
	"github.com/sirupsen/logrus"
	"context"
	"fmt"
)

func main() {
	c, err := api.New()
	if err != nil {
		logrus.Fatal(err)
	}
	ctx := context.Background()
	certs, err := c.GetCertificate(ctx, "k8s.vx-labs.net")
	if err != nil {
		logrus.Fatal(err)
	}
	fmt.Println(certs)
}
