package api

import (
	"golang.org/x/net/context"
	"crypto/rsa"
	"crypto/rand"
	"crypto/tls"
	"github.com/xenolf/lego/acme"
	"crypto"
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
	email        string
	Registration *acme.RegistrationResource
}

func (u Account) GetEmail() string {
	return u.email
}
func (u Account) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u Account) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func New(o ...Opt) (*Client, error) {
	opts := getOpts(o)
	if opts.Email == "" {
		return nil, fmt.Errorf("missing email address")
	}
	if opts.EtcdEndpoints == "" {
		return nil, fmt.Errorf("missing etcd endpoints")
	}
	ctx := context.Background()
	store := cache.NewEtcdProvider(opts.EtcdEndpoints)
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
		logrus.Infof("generating private key")
		key, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}
		logrus.Infof("saving private key")
		err = store.SaveKey(ctx, key)
		if err != nil {
			return nil, err
		}
	} else {
		logrus.Infof("fetched private key from cache")
	}
	account := Account{
		email: opts.Email,
		key:   key,
	}
	var client *acme.Client
	if opts.UseStaging {
		client, err = acme.NewClient("https://acme-staging.api.letsencrypt.org/directory", &account, acme.RSA4096)
	} else {
		client, err = acme.NewClient("https://acme-v01.api.letsencrypt.org/directory", &account, acme.RSA4096)
	}
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
		certList = append(certList, block.Bytes)
		if leaf == nil {
			leaf = cert
		}
	}

	return []tls.Certificate{
		{
			Leaf:        leaf,
			PrivateKey:  c.account.GetPrivateKey(),
			Certificate: certList,
		},
	}, nil
}
