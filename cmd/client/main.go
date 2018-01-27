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
	cert, _, err := c.GetCertificate(context.Background(), "test")
	if err != nil {
		logrus.Fatal(err)
	}
	fmt.Println(cert.Subject.CommonName)
	pem.Encode(os.Stdout, &pem.Block{Bytes: cert.Raw, Type: "CERTIFICATE"})
}