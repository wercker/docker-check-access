package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/docker/distribution/reference"
)

//TokenResp - Contains access token returned from the docker registry after successful authn and authz.
// access token field name can be either "token" or "access_token" in json returned by the registry
type TokenResp struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

//DockerAuth implements Authenticator. It's purpose is to check whether a user has access to a Docker container by checking against a remote registry provider.
type DockerAuth struct {
	token       string
	RegistryURL *url.URL
	username    string
	password    string
}

//GetToken - Returns token string from TokenResp
func (resp TokenResp) GetToken() string {
	if resp.Token != "" {
		return resp.Token
	}
	return resp.AccessToken
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
	n, err := reference.ParseNormalizedNamed(repository)
	if err != nil {
		return "", err
	}
	return reference.Path(n), nil
}

func (d *DockerAuth) Username() string {
	return d.username
}

func (d *DockerAuth) Password() string {
	return d.password
}

func (d *DockerAuth) Repository(repo string) string {
	n, _ := reference.ParseNormalizedNamed(repo)
	return n.Name()
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
	d.token = T.GetToken()
	if d.token == "" {
		return errors.New("Authentication failed")
	}
	return nil
}
