package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2015-07-01/authorization"
	"github.com/Azure/azure-sdk-for-go/services/containerregistry/mgmt/2017-10-01/containerregistry"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

//Azure - struct containing all the fields required for authentication with azure container registry
type Azure struct {
	resourceGroupName string
	registryName      string
	loginServer       string
	subscriptionID    string
	authorizer        autorest.Authorizer
	regClient         containerregistry.RegistriesClient
	roleClient        authorization.RoleAssignmentsClient
	dockerUsername    string
	dockerPassword    string
}

//NewAzure - Creates ServicePrincipleToken and a BearerAuthorizer from it and populates an Azure struct
func NewAzure(clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, registryName, loginServer string) (*Azure, error) {
	spt, err := newServicePrincipalTokenFromCredentials(clientID, clientSecret, tenantID, azure.PublicCloud.ResourceManagerEndpoint)
	if err != nil {
		return nil, err
	}

	authorizer := autorest.NewBearerAuthorizer(spt)
	return &Azure{
		resourceGroupName: resourceGroupName,
		registryName:      registryName,
		loginServer:       loginServer,
		subscriptionID:    subscriptionID,
		authorizer:        authorizer,
		dockerUsername:    clientID,
		dockerPassword:    clientSecret,
	}, nil
}

//CheckAccess - makes a call to Azure to get the registry information.
// If that succeedes. check push access to registry as a standard v2 repository
// using DockerAuth
func (a *Azure) CheckAccess(Repository string, scope Scope) (bool, error) {
	regClient := containerregistry.NewRegistriesClient(a.subscriptionID)
	regClient.Authorizer = a.authorizer
	registry, err := regClient.Get(context.Background(), a.resourceGroupName, a.registryName)
	if err != nil {
		return false, err
	}

	if *registry.LoginServer != a.loginServer {
		return false, errors.New("LoginServer in azure " + *registry.Name + " not same as provided in input: " + a.loginServer)
	}

	//Now validate push access to registry using clientId and clientSecret
	dockerAuth := &DockerAuth{username: a.Username(), password: a.Password()}
	regURL, err := url.Parse("https://" + a.loginServer + "/v2/")
	if err != nil {
		return false, err
	}

	dockerAuth.RegistryURL = regURL
	ok, err := dockerAuth.CheckAccess(Repository, scope)
	if err != nil {
		return false, err
	}

	if !ok {
		return false, errors.New("No push access to the registry")
	}

	return true, nil
}

//Password - returns password for the registry (clientSecret)
func (a *Azure) Password() string {
	return a.dockerPassword
}

//Username - returns username for the registry (cliendId)
func (a *Azure) Username() string {
	return a.dockerUsername
}

//Repository - returns "taggable" repository name
func (a *Azure) Repository(repository string) string {
	return fmt.Sprintf("%s/%s", a.loginServer, repository)
}

func newServicePrincipalTokenFromCredentials(clientID, clientSecret, tenantID, scope string) (*adal.ServicePrincipalToken, error) {
	oauthConfig, err := adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, tenantID)
	if err != nil {
		return nil, err
	}
	return adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, scope)
}
