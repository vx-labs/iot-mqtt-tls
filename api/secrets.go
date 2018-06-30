package api

import (
	"fmt"
	"os"

	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
)

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
