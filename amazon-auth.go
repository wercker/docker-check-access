package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/iam"
)

func getIamPushPerms() []string {
	return []string{
		"AdministratorAccess",
		"AmazonEC2ContainerRegistryPowerUser",
		"PowerUserAccess",
	}
}

// the set of IAM policies that lets a user read from a ecr repository
// aka if you have at least one of these, you can read from the repo

// NOTE: getIamPushPerms and getIamPullPerms are incomplete lists
// of Iam policies that would allow a user to access ECR repositories
func getIamPullPerms() []string {
	return []string{
		"AdministratorAccess",
		"AmazonEC2ContainerRegistryPowerUser",
		"PowerUserAccess",
		"AmazonEC2ContainerRegistryReadOnly",
	}
}

func getResourcePushPerms() []string {
	return []string{"ecr:GetDownloadUrlForLayer",
		"ecr:BatchGetImage",
		"ecr:BatchCheckLayerAvailability",
		"ecr:PutImage",
		"ecr:InitiateLayerUpload",
		"ecr:UploadLayerPart",
		"ecr:CompleteLayerUpload",
	}
}

func getResourcePullPerms() []string {
	return []string{"ecr:GetDownloadUrlForLayer",
		"ecr:BatchGetImage",
		"ecr:BatchCheckLayerAvailability",
	}
}

func compareStringSlices(compareWith, compare []string) bool {
	sort.Strings(compareWith)
	sort.Strings(compare)
	if len(compareWith) != len(compare) {
		return false
	}
	for i := 0; i < len(compare); i++ {
		if compare[i] != compareWith[i] {
			return false
		}
	}
	return true
}

// AmazonAuth implements Authenticator. It's purpose is to check whether or not a certain user with the given accessKey and accessSecret is allowed to interact with a amazon container registry given by registryID in the constructor
type AmazonAuth struct {
	token        string
	registryID   string
	accessKey    string
	accessSecret string
	region       string
	tokenExpire  time.Time
	strictIAM    bool
}

// NewAmazonAuth is a constructor to make the amazon authenticator it takes:
// registryID - the amazon container registry you want to check if a user has permissions on. typically a registryID is an aws account number.
// accessKey - aws user accessKey
// accessSecret - aws user accessSecret
// region - aws region in which your container registry is in
// strictIAM - a flag to that indicates whether or not to check IAM and resource based permissions for a repository. when set to false, don't check them. when set to true, check them.

func NewAmazonAuth(registryID, accessKey, accessSecret, region string, strictIAM bool) *AmazonAuth {
	return &AmazonAuth{registryID: registryID, accessKey: accessKey, accessSecret: accessSecret, region: region, strictIAM: strictIAM}
}

func (a *AmazonAuth) getAuthToken() error {
	conf := aws.NewConfig()
	creds := credentials.NewStaticCredentials(a.accessKey, a.accessSecret, "")
	conf = conf.WithCredentials(creds)
	conf = conf.WithRegion(a.region)
	sess := session.New(conf)
	svc := ecr.New(sess)
	params := &ecr.GetAuthorizationTokenInput{
		RegistryIds: []*string{
			aws.String(a.registryID),
		},
	}
	resp, err := svc.GetAuthorizationToken(params)

	if err != nil {
		return err
	}

	token, _ := base64.StdEncoding.DecodeString(*(resp.AuthorizationData[0].AuthorizationToken))
	idx := strings.Index(string(token), ":")
	// we got something unexpected
	if idx < 0 {
		return ErrUnexpectedResponse
	}
	a.token = string(token)[idx+1:]
	a.tokenExpire = *(resp.AuthorizationData[0].ExpiresAt)
	return nil
}

//GetToken is a getter for the private member token in struct AmazonAuth
//useful if you want to use the token in calls to a remote docker API
func (a AmazonAuth) GetToken() string {
	now := time.Now().Unix()
	if a.token == "" || now > a.tokenExpire.Unix() {
		err := a.getAuthToken()
		if err != nil {
			return ""
		}
	}
	return a.token
}

//GetRepo returns the name of a full amazon ECR repository. It is useful when using making calls to a remote Docker API
func (a AmazonAuth) GetRepo(repo string) string {
	return fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s", a.registryID, a.region, repo)
}

// CheckAccess checks to see if the current amazon user has permissions defined by scope on the given repository
func (a *AmazonAuth) CheckAccess(Repository string, scope Scope) (bool, error) {
	now := time.Now().Unix()
	if a.token == "" || now > a.tokenExpire.Unix() {
		err := a.getAuthToken()
		if err != nil {
			return false, err
		}
	}
	if !a.strictIAM {
		// since we we're able to get a token, we know that the user has access to the repository to a certain degree, don't parse through IAM policies and return true. will lead to false positives.
		return true, nil
	}
	//check to see if the iam policys let the user access the repo
	canAccess, err := a.getPolicyAccess(scope)
	if err != nil {
		return false, err
	}
	if canAccess {
		return canAccess, nil
	}
	//if that doesnt work try looking at the resouce policy and return the results from there
	return a.getResourceAccess(Repository, scope)
}

type PolicyText struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Sid       string          `json:"Sid"`
	Effect    string          `json:"Effect"`
	Principal json.RawMessage `json:"Principal"`
	Action    []string        `json:"Action"`
}

func (a *AmazonAuth) getUser() (string, error) {
	conf := aws.NewConfig()
	creds := credentials.NewStaticCredentials(a.accessKey, a.accessSecret, "")
	conf = conf.WithCredentials(creds)
	conf = conf.WithRegion(a.region)
	sess := session.New(conf)
	svc := iam.New(sess)
	resp, err := svc.GetUser(nil)

	if err != nil {
		return "", err
	}
	return *(resp.User.UserName), nil
}

//check to see if you can get access with iam policies
func (a *AmazonAuth) getPolicyAccess(scope Scope) (bool, error) {
	var IamPerms []string
	if scope == Push {
		IamPerms = getIamPushPerms()
	} else if scope == Pull {
		IamPerms = getIamPullPerms()
	}
	conf := aws.NewConfig()
	creds := credentials.NewStaticCredentials(a.accessKey, a.accessSecret, "")
	conf = conf.WithCredentials(creds)
	conf = conf.WithRegion(a.region)
	sess := session.New(conf)
	svc := iam.New(sess)

	params := &iam.ListPoliciesInput{
		MaxItems:     aws.Int64(20),
		OnlyAttached: aws.Bool(true),
	}
	resp, err := svc.ListPolicies(params)
	if err != nil {
		return false, err
	}
	for _, policy := range resp.Policies {
		name := *(policy.PolicyName)
		for _, allowedPerm := range IamPerms {
			if name == allowedPerm {
				return true, nil
			}
		}
	}
	return false, nil
}

// check the resource pemissions for a repository
func (a AmazonAuth) getResourceAccess(Repository string, scope Scope) (bool, error) {
	conf := aws.NewConfig()
	creds := credentials.NewStaticCredentials(a.accessKey, a.accessSecret, "")
	conf = conf.WithCredentials(creds)
	conf = conf.WithRegion(a.region)
	sess := session.New(conf)
	svc := ecr.New(sess)
	params := &ecr.GetRepositoryPolicyInput{
		RepositoryName: aws.String(Repository),
	}
	resp, err := svc.GetRepositoryPolicy(params)
	if err != nil {
		return false, err
	}
	var policy PolicyText
	err = json.Unmarshal([]byte(*(resp.PolicyText)), &policy)
	if err != nil {
		return false, err
	}
	userName, err := a.getUser()
	if err != nil {
		return false, err
	}
	var canAccess bool
	for _, statement := range policy.Statement {
		dst := make(map[string]string)
		var userStr string
		if bytes.Equal(statement.Principal, ([]byte)("\"*\"")) {
			userStr = "*"
		} else {
			err := json.Unmarshal(statement.Principal, &dst)
			if err != nil {
				return false, err
			}
			if user, ok := dst["AWS"]; ok {
				i := strings.LastIndex(user, "/")
				userStr = user[i+1:]
			} else {
				return false, ErrUnexpectedResponse
			}
		}
		if userStr == "*" || userStr == userName {
			var perms []string
			if scope == Push {
				perms = getResourcePushPerms()
			} else if scope == Pull {
				perms = getResourcePullPerms()
			}
			canAccess = compareStringSlices(statement.Action, perms)
		}
	}
	return canAccess, nil
}
