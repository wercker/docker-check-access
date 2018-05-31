package auth

import (
	"fmt"
	"net/url"

	"github.com/wercker/docker-reg-client/registry"
)

//DockerAuthV1 implements Authenticator. It's purpose is to check whether a user has access to a Docker container by checking against a remote registry provider that still uses the Docker Version 1 registry specification.
//It should be able to call DockerAuth's Username Password and Repository methods
type DockerAuthV1 struct {
	*DockerAuth
}

func NewDockerAuthV1(registryURL *url.URL, username, password string) DockerAuthV1 {
	return DockerAuthV1{
		DockerAuth: NewDockerAuth(registryURL, username, password),
	}
}

func (d DockerAuthV1) CheckAccess(repository string, scope Scope) (bool, error) {
	name, err := d.normalizeRepo(repository)
	if err != nil {
		return false, err
	}
	auth := registry.BasicAuth{
		Username: d.username,
		Password: d.password,
	}
	client := registry.NewClient()
	client.BaseURL = d.RegistryURL
	if scope == Push {
		tokenAuth, err := client.Hub.GetWriteToken(name, auth)
		if err != nil {
			return false, err
		}
		if tokenAuth.Token == "" {
			return false, fmt.Errorf("Not authorized to push to %s%s. Please check username/password and registry/repository values", d.RegistryURL.String(), name)
		}
		return true, nil
	} else if scope == Pull {
		if d.username != "" {
			tokenAuth, err := client.Hub.GetReadTokenWithAuth(name, auth)
			if err != nil {
				return false, err
			}
			if tokenAuth.Token == "" {
				return false, fmt.Errorf("Not authorized to pull from %s%s. Please check username/password and registry/repository values", d.RegistryURL.String(), name)
			}
			return true, nil
		} else {
			tokenAuth, err := client.Hub.GetReadToken(name)
			if err != nil {
				return false, err
			}
			if tokenAuth.Token == "" {
				return false, fmt.Errorf("Not authorized to pull from %s%s. Please check registry/repository values and any authentication requirements for the registry", d.RegistryURL.String(), name)
			}
			return true, nil
		}
	}
	return true, nil
}
