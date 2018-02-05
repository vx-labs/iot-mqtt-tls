package main

import (
	"github.com/vx-labs/iot-mqtt-tls/api"
	"github.com/sirupsen/logrus"
	"context"
	"fmt"
	"os"
	"crypto/tls"
)

func main() {
	c, err := api.New(
		api.WithEmail(os.Getenv("LE_EMAIL")),
		api.WithStagingAPI(),
		api.WithEtcdEndpoints("http://localhost:2379"),
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
