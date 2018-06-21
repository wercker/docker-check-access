package auth

import (
	"net/url"
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
