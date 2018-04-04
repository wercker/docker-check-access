package auth

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/services/authorization/mgmt/2015-07-01/authorization"
	"github.com/Azure/azure-sdk-for-go/services/containerregistry/mgmt/2017-10-01/containerregistry"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

type Azure struct {
	resourceGroupName string
	registryName      string
	registryURL       string
	subscriptionID    string
	authorizer        autorest.Authorizer
	regClient         containerregistry.RegistriesClient
	roleClient        authorization.RoleAssignmentsClient
	dockerUsername    string
	dockerPassword    string
}

func NewAzure(clientID, clientSecret, subscriptionID, tenantID, resourceGroupName, registryName, registryURL string) (*Azure, error) {

	spt, err := newServicePrincipalTokenFromCredentials(clientID, clientSecret, tenantID, azure.PublicCloud.ResourceManagerEndpoint)

	if err != nil {
		return nil, err
	}
	authorizer := autorest.NewBearerAuthorizer(spt)
	return &Azure{
		resourceGroupName: resourceGroupName,
		registryName:      registryName,
		registryURL:       registryURL,
		subscriptionID:    subscriptionID,
		authorizer:        authorizer,
		dockerUsername:    clientID,
		dockerPassword:    clientSecret,
	}, nil
}

func (a *Azure) CheckAccess(Repository string, scope Scope) (bool, error) {
	regClient := containerregistry.NewRegistriesClient(a.subscriptionID)
	regClient.Authorizer = a.authorizer
	registry, err := regClient.Get(context.Background(), a.resourceGroupName, a.registryName)
	if err != nil {
		return false, err
	}

	roleClient := authorization.NewRoleAssignmentsClient(a.subscriptionID)
	roleClient.Authorizer = a.authorizer

	rolesIt, err := roleClient.ListForResourceComplete(context.Background(), a.resourceGroupName, "Microsoft.ContainerRegistry", *(registry.ID), *(registry.Type), *(registry.Name), "atScope()")
	if err != nil {
		return false, err
	}

	canAccess := false
	for role := rolesIt.Value(); rolesIt.NotDone(); rolesIt.Next() {
		if scope == Pull && (*(role.Name) == "Reader" || *(role.Name) == "Contributor") {
			canAccess = true
			break
		} else if scope == Push && *(role.Name) == "Contributor" {
			canAccess = true
			break
		}
	}

	return canAccess, nil
}

func (a *Azure) Password() string {
	return a.dockerPassword
}
func (a *Azure) Username() string {
	return a.dockerUsername
}

func (a *Azure) Repository(repository string) string {
	return fmt.Sprintf("%s/%s", a.registryURL, repository)
}

func newServicePrincipalTokenFromCredentials(clientID, clientSecret, tenantID, scope string) (*adal.ServicePrincipalToken, error) {
	oauthConfig, err := adal.NewOAuthConfig(azure.PublicCloud.ActiveDirectoryEndpoint, tenantID)
	if err != nil {
		return nil, err
	}
	return adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, scope)
}
