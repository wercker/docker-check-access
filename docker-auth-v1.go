package auth

import (
	"net/url"

	"github.com/CenturyLinkLabs/docker-reg-client/registry"
)

//DockerAuthV1 implements Authenticator. It's purpose is to check whether a user has access to a Docker container by checking against a remote registry provider that still uses the Docker Version 1 registry specification.
type DockerAuthV1 struct {
	*DockerAuth
}

func NewDockerAuthV1(registryURL *url.URL, username, password string) *DockerAuthV1 {

	return &DockerAuthV1{
		DockerAuth: NewDockerAuth(registryURL, username, password),
	}
}

func (d *DockerAuthV1) CheckAccess(repository, tag string, scope Scope) (bool, error) {
	name := normalizeRepo(repository)
	auth := registry.BasicAuth{
		Username: d.username,
		Password: d.password,
	}
	client := registry.NewClient()
	client.BaseURL = d.registryURL
	if scope == Push {
		if _, err := client.Hub.GetWriteToken(name, auth); err != nil {
			if err.Error() == "Server returned status 401" || err.Error() == "Server returned status 403" {
				return false, nil
			}
			return false, err
		}
	} else if scope == Pull {
		if d.username != "" {
			if _, err := client.Hub.GetReadTokenWithAuth(name, auth); err != nil {
				if err.Error() == "Server returned status 401" || err.Error() == "Server returned status 403" {
					return false, nil
				}
				return false, err
			}
		} else {
			if _, err := client.Hub.GetReadToken(name); err != nil {
				if err.Error() == "Server returned status 401" || err.Error() == "Server returned status 403" {
					return false, nil
				}
				return false, err
			}
		}
	}
	return true, nil
}
