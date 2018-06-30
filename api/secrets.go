package api

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
)

func wait(name string, retries int, test func() bool) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for retries > 0 {
		if test() {
			return nil
		}
		log.Printf("%s is not ready, waiting for another 5s (%d retries left)", name, retries)
		retries--
		<-ticker.C
	}
	return errors.New("retries expired")
}

func consulWaiter(api *consul.Client) func() bool {
	return func() bool {
		resp, err := api.Status().Leader()
		return err == nil && resp != ""
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
func defaultClients() (*consul.Client, *vault.Client, error) {
	consulConfig := consul.DefaultConfig()
	consulAPI, err := consul.NewClient(consulConfig)
	if err != nil {
		return nil, nil, err
	}
	if wait("consul", 5, consulWaiter(consulAPI)) != nil {
		return nil, nil, errors.New("unable to connect to consul")
	}
	config := vault.DefaultConfig()
	if config.Address == "" {
		config.Address = discoverVaultAddr(consulAPI)
	}
	vaultAPI, err := vault.NewClient(config)
	if err != nil {
		return nil, nil, err
	}
	vaultAPI.SetToken(os.Getenv("VAULT_TOKEN"))
	return consulAPI, vaultAPI, nil
}
