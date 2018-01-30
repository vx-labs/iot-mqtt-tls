package cache

import (
	client "github.com/coreos/etcd/clientv3"
	"strings"
	"os"
	"github.com/sirupsen/logrus"
	"time"
	"golang.org/x/net/context"
	"fmt"
)

const prefix = "/mqtt/tls"

type EtcdProvider struct {
	kv *client.Client
}

func NewEtcdProvider() *EtcdProvider {

	cfg := client.Config{
		Endpoints:   strings.Split(os.Getenv("ETCD_ENDPOINTS"), ","),
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

func (e *EtcdProvider) Get(ctx context.Context, cn string) ([]byte, error) {
	key := fmt.Sprintf("%s/%s", prefix, cn)
	cert, err := e.kv.Get(ctx, key, client.WithLimit(1))
	if err != nil {
		return nil, err
	}
	if len(cert.Kvs) != 1 {
		return nil, fmt.Errorf("specified cn matched %d certificate(s)", len(cert.Kvs))
	}
	return cert.Kvs[0].Value, nil
}

func (e *EtcdProvider) Put(ctx context.Context, cn string, cert []byte) (error) {
	key := fmt.Sprintf("%s/%s", prefix, cn)
	_, err := e.kv.Put(ctx, key, string(cert))
	if err != nil {
		return err
	}
	return nil
}
