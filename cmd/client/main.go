package main

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/vx-labs/iot-mqtt-tls/api"
	"golang.org/x/net/context"
)

func main() {
	c, err := api.New(
		api.WithEmail(os.Getenv("LE_EMAIL")),
		api.WithStagingAPI(),
	)
	if err != nil {
		logrus.Fatal(err)
	}
	ctx := context.Background()
	certs, err := c.GetCertificate(ctx, "k8s.vx-labs.net")
	if err != nil {
		logrus.Fatal(err)
	}
	l, err := tls.Listen("tcp", fmt.Sprintf(":%d", 8000), &tls.Config{
		Certificates: certs,
	})
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("listening on :8000")
	for {
		c, err := l.Accept()
		if err != nil {
			logrus.Warn(err)
			continue
		}
		logrus.Infof("new conn from %s", c.RemoteAddr().String())
		c.Write([]byte("hello !"))
		c.Close()
	}
}
