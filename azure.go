package auth

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/arm/containerregistry"
	"github.com/Azure/go-autorest/autorest/azure"
)

type Azure struct {
	resourceGroupName string
	registryName      string
	registryURL       string
	regClient         containerregistry.RegistriesClient
	dockerUsername    string
	dockerPassword    string
}

func NewAzure(clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, registryName, registryURL string) (*Azure, error) {

	spt, err := newServicePrincipalTokenFromCredentials(clientID, clientSecret, tenantID, azure.PublicCloud.ResourceManagerEndpoint)

	if err != nil {
		return nil, err
	}
	regClient := containerregistry.NewRegistriesClient(subscriptionID)
	regClient.Authorizer = spt
	return &Azure{
		resourceGroupName: resourceGroupName,
		registryName:      registryName,
		registryURL:       registryURL,
		regClient:         regClient,
	}, nil
}

func (a *Azure) CheckAccess(Repository string, scope Scope) (bool, error) {
	res, err := a.regClient.GetCredentials(a.resourceGroupName, a.registryName)
	if err != nil {
		return false, err
	}
	a.dockerUsername = *(res.Username)
	a.dockerPassword = *(res.Password)
	return true, nil
}

func (a *Azure) Password() string {
	var password string
	if a.dockerPassword == "" {
		_, err := a.CheckAccess("", Push)
		if err == nil {
			password = a.dockerPassword
		}
	} else {
		password = a.dockerPassword
	}
	return password
}
func (a *Azure) Username() string {
	var username string
	if a.dockerUsername == "" {
		_, err := a.CheckAccess("", Push)
		if err == nil {
			username = a.dockerUsername
		}
	} else {
		username = a.dockerUsername
	}
	return username
}

func (a *Azure) Repository(repository string) string {
	return fmt.Sprintf("%s/%s", a.registryURL, repository)
}

func newServicePrincipalTokenFromCredentials(clientID, clientSecret, tenantID, scope string) (*azure.ServicePrincipalToken, error) {
	oauthConfig, err := azure.PublicCloud.OAuthConfigForTenant(tenantID)
	if err != nil {
		return nil, err
	}
	return azure.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, scope)
}
