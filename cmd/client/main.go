package main

import (
	"github.com/vx-labs/iot-mqtt-tls/api"
	"github.com/sirupsen/logrus"
	"context"
	"fmt"
	"encoding/pem"
	"os"
)

func main() {
	c, err := api.New("localhost:7995")
	if err != nil {
		logrus.Fatal(err)
	}
	cert, err := c.GetCertificate(context.Background(), "test")
	if err != nil {
		logrus.Fatal(err)
	}
	pem.Encode(os.Stdout, &pem.Block{Bytes: cert[0].Leaf.Raw, Type: "CERTIFICATE"})
}