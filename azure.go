package auth

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2015-07-01/authorization"
	"github.com/Azure/azure-sdk-for-go/services/containerregistry/mgmt/2017-10-01/containerregistry"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

//Azure struct containing all the fields required for authentication with azure container registry
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

//NewAzure creates ServicePrincipleToken and a BearerAuthorizer from it and populates an Azure struct
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

//Password returns password for the registry (clientSecret)
func (a *Azure) Password() string {
	return a.dockerPassword
}

//Username returns username for the registry (cliendId)
func (a *Azure) Username() string {
	return a.dockerUsername
}

//Repository returns "taggable" repository name
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
