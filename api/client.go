package api

import (
	"golang.org/x/net/context"
	"crypto/rsa"
	"crypto/rand"
	"crypto/tls"
	"github.com/xenolf/lego/acme"
	"crypto"
	"os"
	"github.com/vx-labs/iot-mqtt-tls/cache"
	"github.com/sirupsen/logrus"
	"crypto/x509"
	"github.com/xenolf/lego/providers/dns/cloudflare"
	"fmt"
	"encoding/pem"
)

type Client struct {
	api     *acme.Client
	account *Account
}

type Account struct {
	key          *rsa.PrivateKey
	Registration *acme.RegistrationResource
}

func (u Account) GetEmail() string {
	return os.Getenv("LE_EMAIL")
}
func (u Account) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u Account) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func New() (*Client, error) {
	if os.Getenv("LE_EMAIL") == "" {
		return nil, fmt.Errorf("missing email address")
	}
	ctx := context.Background()
	store := cache.NewEtcdProvider()
	m, err := store.Locker(ctx)
	if err != nil {
		return nil, err
	}
	err = m.Lock(ctx)
	if err != nil {
		return nil, err
	}
	defer m.Unlock(ctx)
	key, err := store.GetKey(ctx)
	if err != nil {
		key, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}
		err = store.SaveKey(ctx, key)
		if err != nil {
			return nil, err
		}
	}
	account := Account{
		key: key,
	}
	client, err := acme.NewClient("https://acme-staging.api.letsencrypt.org/directory", &account, acme.RSA4096)
	if err != nil {
		return nil, err
	}
	reg, err := client.Register()
	if err != nil {
		return nil, err
	}
	account.Registration = reg
	err = client.AgreeToTOS()
	if err != nil {
		return nil, err
	}
	c := &Client{
		api:     client,
		account: &account,
	}
	cf, err := cloudflare.NewDNSProvider()
	if err != nil {
		return nil, err
	}
	c.api.ExcludeChallenges([]acme.Challenge{acme.HTTP01})
	err = c.api.SetChallengeProvider(acme.DNS01, cf)
	return c, err
}

func (c *Client) GetCertificate(ctx context.Context, cn string) ([]tls.Certificate, error) {
	bundle := true
	certificates, failures := c.api.ObtainCertificate([]string{cn}, bundle, nil, false)
	if len(failures) > 0 {
		logrus.Fatal(failures)
	}
	var rest = certificates.Certificate
	var block *pem.Block
	var certList [][]byte
	var leaf *x509.Certificate
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("invalid pem data")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certList = append(certList, cert.Raw)
		leaf = cert
	}

	return []tls.Certificate{
		{
			Leaf:        leaf,
			PrivateKey:  c.account.GetPrivateKey(),
			Certificate: certList,
		},
	}, nil
}
