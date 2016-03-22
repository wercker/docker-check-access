package auth

import (
	"net/url"

	"github.com/CenturyLinkLabs/docker-reg-client/registry"
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
	auth := registry.BasicAuth{
		Username: d.username,
		Password: d.password,
	}
	client := registry.NewClient()
	client.BaseURL = d.RegistryURL
	if scope == Push {
		if _, err := client.Hub.GetWriteToken(repository, auth); err != nil {
			if err.Error() == "Server returned status 401" || err.Error() == "Server returned status 403" {
				return false, nil
			}
			return false, err
		}
	} else if scope == Pull {
		if d.username != "" {
			if _, err := client.Hub.GetReadTokenWithAuth(repository, auth); err != nil {
				if err.Error() == "Server returned status 401" || err.Error() == "Server returned status 403" {
					return false, nil
				}
				return false, err
			}
		} else {
			if _, err := client.Hub.GetReadToken(repository); err != nil {
				if err.Error() == "Server returned status 401" || err.Error() == "Server returned status 403" {
					return false, nil
				}
				return false, err
			}
		}
	}
	return true, nil
}
