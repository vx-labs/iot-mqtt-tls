package cache

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"

	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
	"github.com/xenolf/lego/acme"
	"golang.org/x/net/context"
)

const prefix = "mqtt/tls"

type VaultProvider struct {
	vault  *vault.Client
	consul *consul.Client
}

func NewVaultProvider() *VaultProvider {
	consulConfig := consul.DefaultConfig()
	consulAPI, err := consul.NewClient(consulConfig)
	if err != nil {
		panic(err)
	}

	config := vault.DefaultConfig()
	if config.Address == "" {
		config.Address = discoverVaultAddr(consulAPI)
	}
	log.Printf("INFO: connecting to vault at %s", config.Address)
	api, err := vault.NewClient(config)
	if err != nil {
		panic(err)
	}
	return &VaultProvider{
		vault:  api,
		consul: consulAPI,
	}
}

func discoverVaultAddr(client *consul.Client) string {
	opt := &consul.QueryOptions{}
	services, _, err := client.Health().Service("vault", "active", true, opt)
	if err != nil {
		panic(err)
	}
	for _, service := range services {
		return fmt.Sprintf("http://%s:%d", service.Service.Address, service.Service.Port)
	}
	return ""
}
func (e *VaultProvider) savePrivateKey(ctx context.Context, path string, privkey *rsa.PrivateKey) error {
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privkey),
	})
	_, err := e.vault.Logical().Write(path, map[string]interface{}{
		"data": map[string]interface{}{
			"private_key": encoded,
		},
	})
	return err
}

func (e *VaultProvider) getPrivateKey(ctx context.Context, path string) (*rsa.PrivateKey, error) {
	response, err := e.vault.Logical().Read(path)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("key not found")
	}
	data := response.Data["data"]
	if data == nil {
		return nil, fmt.Errorf("key not found")
	}
	kv := data.(map[string]interface{})
	privkey, err := base64.StdEncoding.DecodeString(kv["private_key"].(string))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(privkey))
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func (e *VaultProvider) SaveKey(ctx context.Context, cn string, privkey *rsa.PrivateKey) error {
	key := fmt.Sprintf("secret/data/%s/%s/private_key", prefix, cn)
	return e.savePrivateKey(ctx, key, privkey)
}
func (e *VaultProvider) GetKey(ctx context.Context, cn string) (*rsa.PrivateKey, error) {
	path := fmt.Sprintf("secret/data/%s/%s/private_key", prefix, cn)
	return e.getPrivateKey(ctx, path)
}

func (e *VaultProvider) SaveCert(ctx context.Context, cn string, cert []byte) error {
	key := fmt.Sprintf("secret/data/%s/%s/certificate", prefix, cn)
	_, err := e.vault.Logical().Write(key, map[string]interface{}{
		"data": map[string]interface{}{
			"certificate": cert,
		},
	})
	return err
}

func (e *VaultProvider) GetCert(ctx context.Context, cn string) ([]byte, error) {
	key := fmt.Sprintf("secret/data/%s/%s/certificate", prefix, cn)
	response, err := e.vault.Logical().Read(key)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("certificate not found")
	}
	data := response.Data["data"]
	if data == nil {
		return nil, fmt.Errorf("certificate not found")
	}
	kv := data.(map[string]interface{})
	return base64.StdEncoding.DecodeString(kv["certificate"].(string))
}
func (e *VaultProvider) Lock(ctx context.Context) (*consul.Lock, error) {
	l := NewConsulLocker(e.consul)
	return l.Lock(ctx)
}
func (e *VaultProvider) SaveRegistration(ctx context.Context, reg *acme.RegistrationResource) error {
	payload, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("secret/data/%s/account/registration", prefix)
	_, err = e.vault.Logical().Write(key, map[string]interface{}{
		"data": map[string]interface{}{
			"registration": payload,
		},
	})
	return err
}
func (e *VaultProvider) GetRegistration(ctx context.Context) (*acme.RegistrationResource, error) {
	key := fmt.Sprintf("secret/data/%s/account/registration", prefix)
	response, err := e.vault.Logical().Read(key)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("registration not found")
	}
	data := response.Data["data"]
	if data == nil {
		return nil, fmt.Errorf("registration not found")
	}
	kv := data.(map[string]interface{})
	payload, err := base64.StdEncoding.DecodeString(kv["registration"].(string))
	if err != nil {
		return nil, err
	}
	reg := &acme.RegistrationResource{}
	return reg, json.Unmarshal(payload, reg)
}
