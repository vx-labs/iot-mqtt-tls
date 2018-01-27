package api

import (
	"github.com/vx-labs/iot-mqtt-tls/types"
	"google.golang.org/grpc"
	"io"
	"golang.org/x/net/context"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
)

type Client struct {
	conn io.Closer
	api  types.TLSServiceClient
}

func New(addr string) (*Client, error) {
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	c := &Client{
		conn: conn,
		api:  types.NewTLSServiceClient(conn),
	}
	return c, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) GetCertificate(ctx context.Context, cn string) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.api.GetCertificate(ctx, &types.GetCertificateRequest{
		Domain:   cn,
		Exponent: int64(priv.PublicKey.E),
		Modulus:  priv.PublicKey.N.Bytes(),
	})
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(resp.Certificate)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, err
}
