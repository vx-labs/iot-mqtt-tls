package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
	config "github.com/vx-labs/iot-mqtt-config"
	"github.com/vx-labs/iot-mqtt-tls/cache"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/cloudflare"
	"golang.org/x/net/context"
)

type Client struct {
	api     *acme.Client
	cache   *cache.VaultProvider
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

func newHttpClient(httpConfig config.HTTPSchema) *http.Client {
	client := http.Client{}
	if httpConfig.Proxy != "" {
		proxyURL, err := url.Parse(httpConfig.Proxy)
		if err == nil {
			client.Transport = &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   15 * time.Second,
				ResponseHeaderTimeout: 15 * time.Second,
				ExpectContinueTimeout: 3 * time.Second,
			}
		}
	}
	return &client
}

func New(consulAPI *consul.Client, vaultAPI *vault.Client, o ...Opt) (*Client, error) {
	opts := getOpts(o)
	if opts.Email == "" {
		return nil, fmt.Errorf("missing email address")
	}
	ctx := context.Background()
	prefix := "tls"
	if opts.UseStaging {
		prefix = "tls-staging"
	}
	store := cache.NewVaultProvider(consulAPI, vaultAPI, prefix)
	lock, err := store.Lock(ctx)
	if err != nil {
		return nil, err
	}
	defer lock.Unlock()
	key, err := store.GetKey(ctx, "account")
	if err != nil {
		logrus.Warnf("failed to fetch account key from cache, generating a new one: %v", err)
		key, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}
		logrus.Infof("saving account private key")
		err = store.SaveKey(ctx, "account", key)
		if err != nil {
			logrus.Errorf("failed to save private key: %v", err)
			return nil, err
		}
	} else {
		logrus.Infof("fetched account private key from cache")
	}
	account := Account{
		email: opts.Email,
		key:   key,
	}
	reg, err := store.GetRegistration(ctx)
	if err != nil {
		logrus.Warnf("failed to fetch ACME account from cache")
	} else {
		account.Registration = reg
	}
	c := &Client{
		account: &account,
	}
	httpConfig, _, err := config.HTTP(consulAPI)
	if err != nil {
		return nil, err
	}
	httpClient := newHttpClient(httpConfig)
	acme.HTTPClient = *httpClient
	var client *acme.Client
	if opts.UseStaging {
		client, err = acme.NewClient("https://acme-staging-v02.api.letsencrypt.org/directory", &account, acme.RSA4096)
	} else {
		client, err = acme.NewClient("https://acme-v02.api.letsencrypt.org/directory", &account, acme.RSA4096)
	}
	if err != nil {
		return nil, err
	}

	c.api = client

	cfCreds, err := config.Cloudflare(vaultAPI)
	if err != nil {
		return nil, err
	}
	cfConfig := cloudflare.NewDefaultConfig()
	cfConfig.HTTPClient = newHttpClient(httpConfig)
	cfConfig.AuthEmail = cfCreds.EmailAddress
	cfConfig.AuthKey = cfCreds.APIToken
	cf, err := cloudflare.NewDNSProviderConfig(cfConfig)
	if err != nil {
		return nil, err
	}
	c.api.ExcludeChallenges([]acme.Challenge{acme.HTTP01})
	err = c.api.SetChallengeProvider(acme.DNS01, cf)
	c.cache = store

	if account.Registration == nil {
		reg, err = client.Register(true)
		if err != nil {
			return nil, err
		}
		err = store.SaveRegistration(ctx, reg)
		if err != nil {
			return nil, err
		}
	}
	return c, err
}

func (c *Client) GetCertificate(ctx context.Context, cn string) ([]tls.Certificate, error) {
	l, err := c.cache.Lock(ctx)
	if err != nil {
		return nil, err
	}
	defer l.Unlock()
	key, err := c.cache.GetKey(ctx, cn)
	if err != nil {
		logrus.Infof("generating a new private key")
		key, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}
		err = c.cache.SaveKey(ctx, cn, key)
		if err != nil {
			return nil, err
		}
		logrus.Infof("generated and saved a new private key")
	} else {
		logrus.Infof("fetched key from cache")
	}
	cert, err := c.cache.GetCert(ctx, cn)
	if err != nil {
		logrus.Infof("request certificate from ACME")
		certificates, err := c.api.ObtainCertificate([]string{cn}, true, key, false)
		if err != nil {
			return nil, err
		}
		cert = certificates.Certificate
		logrus.Infof("saving cert to cache")
		err = c.cache.SaveCert(ctx, cn, cert)
		if err != nil {
			logrus.Errorf("failed to save letsencrypt certs: %v", err)
			return nil, err
		}
	}
	encodedKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	tlsCert, err := tls.X509KeyPair(cert, encodedKey)
	if err != nil {
		logrus.Errorf("could not load certificates: %v", err)
		return nil, err
	}
	return []tls.Certificate{
		tlsCert,
	}, nil
}
