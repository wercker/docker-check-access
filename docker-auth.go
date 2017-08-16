package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/docker/docker/reference"
)

type TokenResp struct {
	Token string `json:"token"`
}

//DockerAuth implements Authenticator. It's purpose is to check whether a user has access to a Docker container by checking against a remote registry provider.
type DockerAuth struct {
	token       string
	RegistryURL *url.URL
	username    string
	password    string
}

//NewDockerAuth is a constructor that takes in a remote registry url to check repository permission and basic authentication parameters for API calls to against a Docker Version 2 regisagainst a Docker Version 2 registry provider.
func NewDockerAuth(RegistryURL *url.URL, username, password string) *DockerAuth {
	return &DockerAuth{
		RegistryURL: RegistryURL,
		username:    username,
		password:    password,
	}
}

func (d *DockerAuth) normalizeRepo(repository string) (string, error) {
	n, err := reference.WithName(repository)
	if err != nil {
		return "", err
	}
	return n.RemoteName(), nil
}

//CheckAccess takes a repository and tries to get a JWT token from a docker registry 2 provider, if it succeeds in getting the token, we return true. If there is a failure grabbing the token, we return false and an error explaning what went wrong.
//CheckAccess uses the following flow to get the token: https://docs.docker.com/registry/spec/auth/jwt/A
//Meaning, it tries to make a call with basic auth parameters, and if that doesn't work it tries to request a token from the challenge in the Www-Authenticate header.
func (d *DockerAuth) CheckAccess(repository string, scope Scope) (bool, error) {
	httpClient := http.DefaultClient

	repo, err := d.normalizeRepo(repository)
	if err != nil {
		return false, err
	}

	req, err := d.getRequest(repo, scope)
	if err != nil {
		return false, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	//handle authErrors
	if resp.StatusCode == 404 {
		return false, ErrRepoNotFound
	}
	if resp.StatusCode == 401 {
		authString := resp.Header.Get("Www-Authenticate")
		parts := strings.Split(authString, " ")
		parts = parts[1:]
		tokens := strings.SplitN(parts[0], ",", 3)
		//we have a slice like
		//[realm="https://auth.docker.io/token" service="registry.docker.io" scope="repository:faiq/test-faiq:push,pull"]
		//we want the pieces so time do some splitting & cleaning
		var argsToGetToken []string
		for _, tok := range tokens {
			spl := strings.Split(tok, "=")
			toClean := spl[1]
			cleaned := strings.Trim(toClean, "\"")
			argsToGetToken = append(argsToGetToken, cleaned)
		}
		var err error
		if len(argsToGetToken) == 3 {
			err = d.getToken(argsToGetToken[0], argsToGetToken[1], argsToGetToken[2])
		} else if len(argsToGetToken) == 2 {
			err = d.getToken(argsToGetToken[0], argsToGetToken[1], "")
		}

		if err != nil {
			return false, err
		}
		//now we have a token, so we try the request again
		req, err := d.getRequest(repo, scope)
		if err != nil {
			return false, err
		}
		d.authenticate(req)
		resp, err := httpClient.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		statusCode := resp.StatusCode
		if statusCode == 200 || statusCode == 202 {
			return true, nil
		}

		if resp.StatusCode == 404 {
			return false, ErrRepoNotFound
		}
	}
	// if the remote server gives us the go ahead, we're fine
	// used for registries like GCR which might use some other sort of authz strategy
	if resp.StatusCode == 200 || resp.StatusCode == 202 {
		return true, nil

	}
	return false, ErrUnexpectedResponse
}

func (d *DockerAuth) Username() string {
	return d.username
}

func (d *DockerAuth) Password() string {
	return d.password
}

func (d *DockerAuth) Repository(repo string) string {
	n, _ := reference.WithName(repo)
	return n.FullName()
}

//gives you proper request based on repo tag and scope
func (d *DockerAuth) getRequest(repo string, scope Scope) (*http.Request, error) {
	if scope == Pull {
		return d.buildPullReq(repo)
	} else {
		return d.buildPushReq(repo)
	}
}

func (d *DockerAuth) buildPullReq(repo string) (*http.Request, error) {
	rel, err := url.Parse(fmt.Sprintf("/v2/%s/tags/list", repo))
	if err != nil {
		return nil, err
	}
	u := d.RegistryURL.ResolveReference(rel)
	return http.NewRequest("GET", u.String(), nil)
}

func (d *DockerAuth) buildPushReq(repo string) (*http.Request, error) {
	rel, err := url.Parse(fmt.Sprintf("/v2/%s/blobs/uploads/", repo))
	if err != nil {
		return nil, err
	}
	u := d.RegistryURL.ResolveReference(rel)
	return http.NewRequest("POST", u.String(), nil)
}

func (d *DockerAuth) authenticate(req *http.Request) {
	if d.username != "" && d.password != "" && d.token == "" {
		req.SetBasicAuth(d.username, d.password)
	} else if d.token != "" {
		// use Authorization
		req.Header.Set("Authorization", "Bearer "+d.token)
	}
	// do nothing if there is no basic auth
}

func (d *DockerAuth) getToken(realm, service, scope string) error {
	v := url.Values{}
	v.Add("service", service)
	if scope != "" {
		v.Add("scope", scope)
	}
	//check to see if its a url
	_, err := url.Parse(realm)
	if err != nil {
		return err
	}
	encoded := v.Encode()
	urlString := realm + "?" + encoded
	req, err := http.NewRequest("GET", urlString, nil)
	if err != nil {
		return err
	}
	//set basic auth only if you have credentials
	if d.username != "" && d.password != "" {
		req.SetBasicAuth(d.username, d.password)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var T TokenResp
	json.NewDecoder(resp.Body).Decode(&T)
	d.token = T.Token
	if d.token == "" {
		return errors.New("Authentication failed")
	}
	return nil
}
