package cache

import (
	client "github.com/coreos/etcd/clientv3"
	"strings"
	"github.com/sirupsen/logrus"
	"time"
	"golang.org/x/net/context"
	"fmt"
	"crypto/rsa"
	"crypto/x509"
	"github.com/coreos/etcd/clientv3/concurrency"
)

const prefix = "/mqtt/tls"

type EtcdProvider struct {
	kv *client.Client
}

type Locker interface {
	Lock(ctx context.Context) error
	Unlock(ctx context.Context) error
}

func NewEtcdProvider(endpoints string) *EtcdProvider {

	cfg := client.Config{
		Endpoints:   strings.Split(endpoints, ","),
		DialTimeout: 1 * time.Second,
	}
	c, err := client.New(cfg)
	if err != nil {
		for {
			logrus.Errorf("Cannot create etcd store: %s - will retry in 5s", err)
			<-time.After(5 * time.Second)
			c, err = client.New(cfg)
			if err == nil {
				break
			}
		}
	}
	p := &EtcdProvider{
		kv: c,
	}
	return p
}

func (e *EtcdProvider) Locker(ctx context.Context) (Locker, error) {
	lockKey := fmt.Sprintf("%s/lock", prefix)
	session, err := concurrency.NewSession(e.kv)
	if err != nil {
		return nil, err
	}
	m := concurrency.NewMutex(session, lockKey)
	if err := m.Lock(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

func (e *EtcdProvider) SaveCerts(ctx context.Context, cn string, certs []byte, privkey []byte) (error) {
	key := fmt.Sprintf("%s/%s/cert", prefix, cn)
	_, err := e.kv.Put(ctx, key, string(certs))
	if err != nil {
		return err
	}
	key = fmt.Sprintf("%s/%s/_private", prefix, cn)
	_, err = e.kv.Put(ctx, key, string(privkey))
	if err != nil {
		return err
	}
	return nil
}

func (e *EtcdProvider) GetCerts(ctx context.Context, cn string) ([]byte, []byte, error) {
	key := fmt.Sprintf("%s/%s/cert", prefix, cn)
	response, err := e.kv.Get(ctx, key, client.WithLimit(1))
	if err != nil {
		return nil, nil, err
	}
	if len(response.Kvs) != 1 {
		return nil, nil, fmt.Errorf("certificates not found")
	}
	certificate := response.Kvs[0].Value
	key = fmt.Sprintf("%s/%s/_private", prefix, cn)
	response, err = e.kv.Get(ctx, key, client.WithLimit(1))
	if err != nil {
		return nil, nil, err
	}
	if len(response.Kvs) != 1 {
		return nil, nil, fmt.Errorf("private key not found")
	}
	privkey := response.Kvs[0].Value
	return certificate, privkey, nil

}

func (e *EtcdProvider) SaveKey(ctx context.Context, cn string, privkey *rsa.PrivateKey) (error) {
	key := fmt.Sprintf("c", prefix, cn)
	payload := x509.MarshalPKCS1PrivateKey(privkey)
	_, err := e.kv.Put(ctx, key, string(payload))
	if err != nil {
		return err
	}
	return nil
}
func (e *EtcdProvider) GetKey(ctx context.Context, cn string) (*rsa.PrivateKey, error) {
	key := fmt.Sprintf("%s/%s/_private", prefix, cn)
	response, err := e.kv.Get(ctx, key, client.WithLimit(1))
	if err != nil {
		return nil, err
	}
	if len(response.Kvs) != 1 {
		return nil, fmt.Errorf("specified cn matched %d private key(s)", len(response.Kvs))
	}
	return x509.ParsePKCS1PrivateKey(response.Kvs[0].Value)

}
func (e *EtcdProvider) Get(ctx context.Context, cn string, modulus string) ([]byte, error) {
	key := fmt.Sprintf("%s/%s/%s", prefix, cn, modulus)
	cert, err := e.kv.Get(ctx, key, client.WithLimit(1))
	if err != nil {
		return nil, err
	}
	if len(cert.Kvs) != 1 {
		return nil, fmt.Errorf("specified cn matched %d certificate(s)", len(cert.Kvs))
	}
	return cert.Kvs[0].Value, nil
}

func (e *EtcdProvider) Put(ctx context.Context, cn string, modulus string, cert []byte) (error) {
	key := fmt.Sprintf("%s/%s/%s", prefix, cn, modulus)
	_, err := e.kv.Put(ctx, key, string(cert))
	if err != nil {
		return err
	}
	return nil
}
