package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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

//quay.io/wercker/badasscontainer -> wercker/badasscontainer
//wecker/badass -> wercker/badass
//see : https://github.com/wercker/wercker/blob/master/docker/docker.go#L283#L297
func normalizeRepo(name string) string {
	parts := strings.Split(name, "/")
	if len(parts) == 1 {
		return name
	}

	for strings.Contains(parts[0], ".") {
		parts = parts[1:]
	}

	return strings.Join(parts, "/")
}

//CheckAccess takes a repository and tries to get a JWT token from a docker registry 2 provider, if it succeeds in getting the token, we return true. If there is a failure grabbing the token, we return false and an error explaning what went wrong.
//CheckAccess uses the following flow to get the token: https://docs.docker.com/registry/spec/auth/jwt/A
//Meaning, it tries to make a call with basic auth parameters, and if that doesn't work it tries to request a token from the challenge in the Www-Authenticate header.
func (d *DockerAuth) CheckAccess(repository, tag string, scope Scope) (bool, error) {
	httpClient := http.DefaultClient
	repo := normalizeRepo(repository)
	var req *http.Request
	var err error
	if scope == Pull {
		req, err = d.buildPullReq(repo, tag)
		if err != nil {
			return false, err
		}
	} else if scope == Push {
		req, err = d.buildPushReq(repo)
		if err != nil {
			return false, err
		}
	}
	// try without auth so we can get WWW-Authenticate challenge
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	//handle authErrors
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
		//now we have a token, so we try the pull request again
		req, err = d.buildPullReq(repo, tag)
		d.authenticate(req)
		resp, err := httpClient.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			return true, nil
		}
	}
	return false, ErrUnexpectedResponse
}

func (d DockerAuth) buildPullReq(repo, tag string) (*http.Request, error) {
	rel, err := url.Parse(fmt.Sprintf("/v2/%s/manifests/%s", repo, tag))
	if err != nil {
		return nil, err
	}
	u := d.RegistryURL.ResolveReference(rel)
	return http.NewRequest("GET", u.String(), nil)
}

func (d DockerAuth) buildPushReq(repo string) (*http.Request, error) {
	rel, err := url.Parse(fmt.Sprintf("/v2/%s/blobs/uploads", repo))
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
	//
	if d.token == "" {
		return errors.New("No Token found")
	}
	return nil
}
