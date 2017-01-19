package auth

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/arm/containerregistry"
	"github.com/Azure/go-autorest/autorest/azure"
)

type Azure struct {
	clientID          string
	clientSecret      string
	subscriptionID    string
	tenantID          string
	resourceGroupName string
	registryName      string
	registryURL       string
	regClient         containerregistry.RegistriesClient
	dockerUsername    string
	dockerPassword    string
}

func NewAzure(clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, registryName, registryURL string) (*Azure, error) {
	c := map[string]string{
		"AZURE_CLIENT_ID":       clientID,
		"AZURE_CLIENT_SECRET":   clientSecret,
		"AZURE_SUBSCRIPTION_ID": subscriptionID,
		"AZURE_TENANT_ID":       tenantID,
	}

	spt, err := newServicePrincipalTokenFromCredentials(c, azure.PublicCloud.ResourceManagerEndpoint)
	if err != nil {
		return nil, err
	}
	regClient := containerregistry.NewRegistriesClient(c["AZURE_SUBSCRIPTION_ID"])
	regClient.Authorizer = spt
	return &Azure{
		clientID:          clientID,
		clientSecret:      clientSecret,
		subscriptionID:    subscriptionID,
		tenantID:          tenantID,
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

func newServicePrincipalTokenFromCredentials(c map[string]string, scope string) (*azure.ServicePrincipalToken, error) {
	oauthConfig, err := azure.PublicCloud.OAuthConfigForTenant(c["AZURE_TENANT_ID"])
	if err != nil {
		panic(err)
	}
	return azure.NewServicePrincipalToken(*oauthConfig, c["AZURE_CLIENT_ID"], c["AZURE_CLIENT_SECRET"], scope)
}
