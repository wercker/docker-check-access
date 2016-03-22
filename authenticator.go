package auth

//Scope defines the possible types of scopes
type Scope string

const (
	Push Scope = "PUSH"
	Pull Scope = "PULL"
)

// An Authenticator is the interface that wraps the CheckAccess method
// It implements 4 methods:
// CheckAccess - which checks to see if a user is allowed to read and write to a certain docker repository specefied by a repository name
// Password - which returns the password for any authenticator object, or any token an external service such as Amazon ECR or Google GCR might return to use as a password
// Username which return the username for any authenticator object, or any defualt username an external service such as Amazon ECR or Google GCR might use
// Repository returns the full normalized repository name
type Authenticator interface {
	CheckAccess(string, Scope) (bool, error)
	Password() string
	Username() string
	Repository(string) string
}
